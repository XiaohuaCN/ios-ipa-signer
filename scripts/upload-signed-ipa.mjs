import https from 'node:https';
import http from 'node:http';
import { open, stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createTransferProgress } from './transfer-progress.mjs';

// One process and pooled TLS connections for the entire sequential upload.
// Never follow redirects carrying credentials or print signed storage URLs.
export function createTransport({ allowHttp = false, connectMs = 15000, idleMs = 20000, totalMs = 120000 } = {}) {
  const agents = {
    'https:': new https.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1, scheduling: 'lifo' }),
    'http:': new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1, scheduling: 'lifo' }),
  };
  const stats = { requests: 0, reused: 0 };
  return {
    stats,
    close() { for (const agent of Object.values(agents)) agent.destroy(); },
    request(target, { method = 'POST', headers = {}, body = Buffer.alloc(0), deadlineMs = totalMs, idleTimeoutMs = idleMs } = {}) {
      return new Promise((resolve, reject) => {
        let url;
        try {
          url = new URL(target);
          if ((url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) || url.username || url.password || url.hash) throw new Error();
        } catch { reject(Object.assign(new Error('Invalid upload endpoint'), { code: 'EENDPOINT' })); return; }
        const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
        const client = url.protocol === 'https:' ? https : http;
        let done = false, connectionTimer, deadlineTimer;
        const finish = (error, result) => {
          if (done) return;
          done = true;
          clearTimeout(connectionTimer);
          clearTimeout(deadlineTimer);
          req.setTimeout(0);
          error ? reject(error) : resolve(result);
        };
        const req = client.request(url, {
          method, agent: agents[url.protocol],
          headers: { ...headers, 'content-length': String(bytes.length) },
        }, response => {
          const chunks = [];
          let length = 0;
          response.on('data', chunk => {
            length += chunk.length;
            if (length > 1024 * 1024) req.destroy(Object.assign(new Error('Response too large'), { code: 'EPROTOCOL' }));
            else chunks.push(chunk);
          });
          response.on('error', error => finish(error));
          response.on('aborted', () => finish(Object.assign(new Error('Response interrupted'), { code: 'ECONNRESET' })));
          response.on('end', () => finish(null, { status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString('utf8') }));
        });
        stats.requests++;
        const timedOut = code => req.destroy(Object.assign(new Error(code), { code }));
        connectionTimer = setTimeout(() => timedOut('ECONNECTTIMEOUT'), connectMs);
        deadlineTimer = setTimeout(() => timedOut('EDEADLINE'), deadlineMs);
        req.on('socket', socket => {
          if (req.reusedSocket) stats.reused++;
          if (!socket.connecting) clearTimeout(connectionTimer);
          else socket.once(url.protocol === 'https:' ? 'secureConnect' : 'connect', () => clearTimeout(connectionTimer));
          // This tracks socket inactivity, not merely elapsed upload time.
          req.setTimeout(Math.min(idleTimeoutMs, deadlineMs), () => timedOut('ESTALLED'));
        });
        req.on('error', error => finish(error));
        req.end(bytes);
      });
    },
  };
}

function safeCode(error) {
  const code = String(error?.code || 'EUPLOAD');
  return /^[A-Z][A-Z0-9_]{0,40}$/.test(code) ? code : 'EUPLOAD';
}
function protocolError() { return Object.assign(new Error('Invalid upload response'), { code: 'EPROTOCOL' }); }
function jsonResponse(response, openList = false) {
  if (response.status < 200 || response.status >= 300) {
    throw Object.assign(new Error('Upload HTTP ' + response.status), {
      code: 'HTTP_' + response.status,
      retryable: response.status === 408 || response.status === 429 || response.status >= 500,
    });
  }
  let data;
  try { data = JSON.parse(response.text); } catch { throw protocolError(); }
  if (openList) {
    if (data.code !== 200 || !data.data) throw protocolError();
    return data.data;
  }
  return data;
}
export async function withRetry(operation, { attempts = 3, log = console.error, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try { return await operation(); } catch (error) {
      if (error.retryable === false || ['EENDPOINT', 'EPROTOCOL'].includes(safeCode(error)) || attempt === attempts) throw error;
      log(`Upload retry ${attempt}/${attempts - 1}: ${safeCode(error)}`);
      await sleep(Math.min(8000, 1000 * 2 ** attempt));
    }
  }
}
function mask(value, output) {
  if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) throw protocolError();
  output('::add-mask::' + value.replace(/%/g, '%25'));
  return value;
}
function secureUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw protocolError(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw protocolError();
  return url.href;
}
function ossTicket(ticket) {
  const upload = new URL(secureUrl(ticket.upload_url));
  const download = new URL(secureUrl(ticket.signed_ipa_url));
  if (!/^[a-z0-9-]+\.oss-(?:accelerate|[a-z0-9-]+)\.aliyuncs\.com$/.test(upload.hostname) ||
      download.hostname !== upload.hostname.replace('.oss-accelerate.', '.oss-cn-hangzhou.') ||
      download.pathname !== upload.pathname || download.search ||
      ticket.upload_headers?.['Content-Type'] !== 'application/octet-stream') throw protocolError();
  return { upload: upload.href, download: download.href };
}
// Only the public output URL reaches stdout. The private upload URL is fed
// through stdin, never included in process arguments or curl diagnostics.
export function curlPut({ file, url, deadlineMs, size = 0, log = console.error, progressIntervalMs = 5000, allowHttp = false }) {
  return new Promise((resolve, reject) => {
    const quote = value => '"' + String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    const child = spawn('curl', ['--disable', '--progress-meter', '--proto', allowHttp ? '=http,https' : '=https', '--connect-timeout', '20',
      '--max-time', String(Math.max(1, Math.floor(deadlineMs / 1000))), '--speed-limit', '1024', '--speed-time', '90',
      '--upload-file', file, '--output', '/dev/null', '--write-out', '%{http_code} %{size_upload} %{time_total}', '--config', '-'],
    { stdio: ['pipe', 'pipe', 'pipe'] });
    const progress = createTransferProgress('upload', { total: size, log, intervalMs: progressIntervalMs });
    child.stderr.on('data', chunk => progress.push(chunk));
    let output = '', tooLarge = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), deadlineMs + 1000);
    child.stdout.on('data', bytes => { output += bytes; if (output.length > 1024) { tooLarge = true; child.kill(); } });
    child.stdin.on('error', () => {});
    child.on('error', () => { clearTimeout(timer); reject(Object.assign(new Error('Upload process unavailable'), { code: 'EPROCESS', retryable: false })); });
    child.on('close', code => {
      clearTimeout(timer);
      progress.end();
      if (tooLarge) return reject(protocolError());
      if (code !== 0) return reject(Object.assign(new Error('Storage connection interrupted'), { code: 'ECURL_' + (Number.isInteger(code) ? code : 'TIMEOUT') }));
      const fields = output.trim().split(/\s+/);
      if (fields.length !== 3 || !/^\d{3}$/.test(fields[0]) || !Number.isFinite(Number(fields[1]))) return reject(protocolError());
      resolve({ status: Number(fields[0]), bytes: Number(fields[1]) });
    });
    child.stdin.end('url = ' + quote(url) + '\nheader = "Content-Type: application/octet-stream"\n');
  });
}
export async function uploadOssFile({ file, size, ticket, getTicket, put = curlPut, log = console.error, sleep, now = Date.now, budgetMs = 30 * 60 * 1000 }) {
  if (!Number.isSafeInteger(size) || size <= 0) throw protocolError();
  const started = now();
  let attempt = 0;
  log('Upload route: direct OSS' + (new URL(ossTicket(ticket).upload).hostname.includes('.oss-accelerate.') ? ' (transfer acceleration)' : ' (regional endpoint)'));
  return withRetry(async () => {
    const remaining = budgetMs - (now() - started);
    if (remaining <= 0) throw Object.assign(new Error('Upload deadline exceeded'), { code: 'EUPLOADDEADLINE', retryable: false });
    const current = attempt++ === 0 ? ticket : await getTicket();
    const urls = ossTicket(current);
    mask(urls.upload, log); mask(urls.download, log);
    const response = await put({ file, url: urls.upload, deadlineMs: remaining, size, log });
    if (response.status < 200 || response.status >= 300) throw Object.assign(new Error('Storage HTTP ' + response.status), {
      code: 'HTTP_' + response.status, retryable: [403, 408, 429].includes(response.status) || response.status >= 500,
    });
    if (response.bytes !== size) throw protocolError();
    log(`Upload complete: ${(size / 1048576).toFixed(2)} MiB in ${((now() - started) / 1000).toFixed(2)}s`);
    return urls.download;
  }, { log, sleep });
}
export async function uploadParts({ session, size, readPart, transport, servicePost, log = console.error, sleep, now = Date.now, budgetMs = 30 * 60 * 1000 }) {
  const chunkSize = Number(session.chunk_size), total = Number(session.total_chunks);
  if (!Number.isSafeInteger(size) || size <= 0 || !Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > 64 * 1024 * 1024 || total !== Math.ceil(size / chunkSize)) throw protocolError();
  const relayUrl = secureUrl(session.direct_upload_url);
  mask(relayUrl, log);
  const remoteId = String(session.direct_remote_upload_id || '');
  if (!remoteId || !session.upload_id) throw protocolError();
  const token = mask(session.direct_upload_token, log);
  let resume = mask(session.direct_resume_token, log);
  let uploaded = 0;
  const started = now();
  const remaining = () => {
    const milliseconds = budgetMs - (now() - started);
    if (milliseconds <= 0) throw Object.assign(new Error('Upload deadline exceeded'), { code: 'EUPLOADDEADLINE', retryable: false });
    return milliseconds;
  };
  log(`Upload route: Cloudflare OpenList relay; ${total} parts; 180s per-part deadline`);
  for (let index = 0; index < total; index++) {
    remaining();
    const partStart = now();
    const expected = Math.min(chunkSize, size - index * chunkSize);
    const bytes = await readPart(index * chunkSize, expected);
    if (!Buffer.isBuffer(bytes) || bytes.length !== expected) throw protocolError();
    const remoteHeaders = () => ({ authorization: token, 'x-upload-id': remoteId, 'x-upload-session': resume });
    const remote = await withRetry(async () => jsonResponse(await transport.request(relayUrl, {
        method: 'PUT', headers: { ...remoteHeaders(), 'x-chunk-index': String(index), 'content-type': 'application/octet-stream' }, body: bytes,
        deadlineMs: Math.min(180000, remaining()), idleTimeoutMs: 120000,
      }), true), { log, sleep });
    resume = mask(remote.resume_token, log);
    uploaded += expected;
    const seconds = (now() - started) / 1000;
    log(`Uploaded signed IPA part ${index + 1}/${total} (relay) in ${((now() - partStart) / 1000).toFixed(2)}s; ${(uploaded / 1048576).toFixed(1)} MiB; avg ${(uploaded / 1048576 / Math.max(seconds, 0.001)).toFixed(2)} MiB/s`);
  }
  remaining();
  const complete = await servicePost('/api/signing/multipart/complete', { upload_id: session.upload_id }, { 'x-openlist-upload-session': resume });
  const result = secureUrl(complete.signed_ipa_url);
  mask(result, log);
  const seconds = (now() - started) / 1000;
  log(`Upload complete: ${(size / 1048576).toFixed(2)} MiB in ${seconds.toFixed(2)}s; pooled requests=${transport.stats.requests}, reused=${transport.stats.reused}`);
  return result;
}

export async function main(file = process.argv[2] || 'signed.ipa') {
  const base = secureUrl(process.env.SIGNING_SERVICE_URL);
  const token = process.env.SIGNING_SERVICE_TOKEN;
  const jobId = process.env.SIGNED_UPLOAD_JOB_ID, claimToken = process.env.SIGNED_UPLOAD_CLAIM_TOKEN;
  if (!token || !jobId || !claimToken) throw protocolError();
  const transport = createTransport();
  let handle;
  try {
    const size = (await stat(file)).size;
    const servicePost = (path, data, headers = {}) => withRetry(async () => jsonResponse(await transport.request(new URL(path, base), {
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ job_id: jobId, claim_token: claimToken, ...data }),
    })));
    const initStarted = Date.now();
    const getTicket = () => servicePost('/api/signing/upload-ticket', {});
    const ticket = await getTicket();
    if (ticket.storage === 'oss' || (!ticket.storage && /^https:\/\/[a-z0-9-]+\.oss-[a-z0-9-]+\.aliyuncs\.com\//.test(ticket.upload_url || ''))) {
      const result = await uploadOssFile({ file, size, ticket, getTicket });
      process.stdout.write(result + '\n');
      return;
    }
    if (ticket.storage && ticket.storage !== 'openlist') throw protocolError();
    console.error('Preparing storage upload session');
    const session = await servicePost('/api/signing/multipart/init', { size_bytes: size });
    console.error(`OpenList upload session ready in ${((Date.now() - initStarted) / 1000).toFixed(2)}s`);
    handle = await open(file, 'r');
    const result = await uploadParts({ session, size, transport, servicePost,
      readPart: async (position, length) => {
        const bytes = Buffer.alloc(length);
        let offset = 0;
        while (offset < length) {
          const read = await handle.read(bytes, offset, length - offset, position + offset);
          if (!read.bytesRead) throw protocolError();
          offset += read.bytesRead;
        }
        return bytes;
      },
    });
    // Only this URL goes to stdout: the workflow captures it, never logs it.
    process.stdout.write(result + '\n');
  } finally {
    await handle?.close();
    transport.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error('Signed IPA upload failed: ' + safeCode(error)); process.exitCode = 1; });
}
