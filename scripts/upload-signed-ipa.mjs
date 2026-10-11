import https from 'node:https';
import http from 'node:http';
import { open, stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

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
      log(`Upload retry ${attempt}/${attempts - 1}: ${safeCode(error)}; retrying the same part`);
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
function secureProviderUrl(value) {
  const target = secureUrl(value);
  const host = new URL(target).hostname.toLowerCase();
  if (!host.endsWith('.aliyundrive.net') && !host.endsWith('.aliyunpds.com')) throw protocolError();
  return target;
}

export async function uploadParts({ session, size, readPart, transport, servicePost, log = console.error, sleep }) {
  const chunkSize = Number(session.chunk_size), total = Number(session.total_chunks);
  if (!Number.isSafeInteger(size) || size <= 0 || !Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > 64 * 1024 * 1024 || total !== Math.ceil(size / chunkSize)) throw protocolError();
  const relayUrl = secureUrl(session.direct_upload_url);
  mask(relayUrl, log);
  const remoteId = String(session.direct_remote_upload_id || '');
  if (!remoteId || !session.upload_id) throw protocolError();
  const token = mask(session.direct_upload_token, log);
  let resume = mask(session.direct_resume_token, log);
  let uploaded = 0;
  const started = Date.now();
  log(`Upload route: direct provider first; ${total} parts; 180s per-part deadline`);
  const partControl = secureUrl(session.direct_part_urls_url), ackControl = secureUrl(session.direct_ack_url);
  mask(partControl, log); mask(ackControl, log);
  if (new URL(partControl).origin !== new URL(relayUrl).origin || new URL(ackControl).origin !== new URL(relayUrl).origin) throw protocolError();
  for (let index = 0; index < total; index++) {
    const partStart = Date.now();
    const expected = Math.min(chunkSize, size - index * chunkSize);
    const bytes = await readPart(index * chunkSize, expected);
    if (!Buffer.isBuffer(bytes) || bytes.length !== expected) throw protocolError();
    let remote, route = 'direct', providerAccepted = false;
    const remoteHeaders = () => ({ authorization: token, 'x-upload-id': remoteId, 'x-upload-session': resume });
    try {
      await withRetry(async () => {
        const urls = jsonResponse(await transport.request(partControl, {
          headers: { ...remoteHeaders(), 'content-type': 'application/json' }, body: JSON.stringify({ indices: [index] }),
        }), true);
        if (urls.resume_token) resume = mask(urls.resume_token, log);
        const signedUrl = secureProviderUrl(urls.parts?.find(part => part.index === index)?.upload_url);
        mask(signedUrl, log);
        // Do not add Content-Type: it changes the provider's signed PUT request.
        const uploadedPart = await transport.request(signedUrl, {
          method: 'PUT', body: bytes, deadlineMs: 180000, idleTimeoutMs: 90000,
        });
        if (uploadedPart.status !== 200) throw Object.assign(new Error('Provider rejected part'), {
          code: 'HTTP_' + uploadedPart.status,
          retryable: uploadedPart.status === 403 || uploadedPart.status === 408 || uploadedPart.status === 429 || uploadedPart.status >= 500,
        });
      }, { log, sleep });
      providerAccepted = true;
      // Retry acknowledgement without retransmitting bytes if the control
      // request stalls after the provider accepted the part.
      remote = await withRetry(async () => jsonResponse(await transport.request(ackControl, {
        headers: { ...remoteHeaders(), 'content-type': 'application/json' }, body: JSON.stringify({ indices: [index] }),
      }), true), { log, sleep });
    } catch (error) {
      // A failed acknowledgement is ambiguous: the provider may already
      // have accepted the bytes. Let the job retry instead of relaying twice.
      if (providerAccepted) throw error;
      if (error.retryable === false || ['EENDPOINT', 'EPROTOCOL'].includes(safeCode(error))) throw error;
      log('Direct provider route unavailable; trying OpenList relay for this part');
      remote = await withRetry(async () => jsonResponse(await transport.request(relayUrl, {
        method: 'PUT', headers: { ...remoteHeaders(), 'x-chunk-index': String(index), 'content-type': 'application/octet-stream' }, body: bytes,
        deadlineMs: 180000, idleTimeoutMs: 60000,
      }), true), { log, sleep });
      route = 'relay';
    }
    resume = mask(remote.resume_token, log);
    uploaded += expected;
    const seconds = (Date.now() - started) / 1000;
    log(`Uploaded signed IPA part ${index + 1}/${total} (${route}) in ${((Date.now() - partStart) / 1000).toFixed(2)}s; ${(uploaded / 1048576).toFixed(1)} MiB; avg ${(uploaded / 1048576 / Math.max(seconds, 0.001)).toFixed(2)} MiB/s`);
  }
  const complete = await servicePost('/api/signing/multipart/complete', { upload_id: session.upload_id }, { 'x-openlist-upload-session': resume });
  const result = secureUrl(complete.signed_ipa_url);
  mask(result, log);
  const seconds = (Date.now() - started) / 1000;
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
    console.error('Preparing OpenList upload session');
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
