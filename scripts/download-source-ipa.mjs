import { spawn, execFile } from 'node:child_process';
import { mkdtemp, stat, rename, rm } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

const exec = promisify(execFile);
const error = code => Object.assign(new Error(code), { code });
const transientCurlCodes = new Set([5, 6, 7, 18, 28, 35, 52, 55, 56, 92, 95]);

export function retryableCurl(code, status) {
  return transientCurlCodes.has(code) || (code === 22 && (status === 408 || status === 429 || status >= 500));
}

export function curlDownload(url, file, { allowHttp = false, connectSeconds = 15, idleSeconds = 20, maxSeconds = 900 } = {}) {
  const protocol = allowHttp ? '=http,https' : '=https';
  return new Promise((resolveResult, reject) => {
    // Keep source/signed redirect URLs out of argv, logs, and curl stderr.
    const child = spawn('curl', [
      '--disable', '--config', '-', '--fail', '--location', '--max-redirs', '10',
      '--proto', protocol, '--proto-redir', protocol,
      '--connect-timeout', String(connectSeconds), '--speed-limit', '1024',
      '--speed-time', String(idleSeconds), '--max-time', String(maxSeconds),
      '--silent', '--show-error', '--output', file, '--write-out', '%{http_code}',
    ], { stdio: ['pipe', 'pipe', 'ignore'] });
    let status = '';
    child.stdout.on('data', bytes => { if (status.length < 100) status += bytes.toString(); });
    child.on('error', () => reject(error('ECURL')));
    child.on('close', code => resolveResult({ code: Number.isInteger(code) ? code : -1, status: Number(status.trim()) || 0 }));
    child.stdin.on('error', () => {});
    child.stdin.end('url = "' + url.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"\n');
  });
}

export async function validateIpa(file) {
  try {
    // CRC-check the entire ZIP; an HTML error page must never reach signing.
    await exec('unzip', ['-tq', file], { maxBuffer: 1024 * 1024 });
    const { stdout } = await exec('unzip', ['-Z1', file], { maxBuffer: 16 * 1024 * 1024 });
    if (stdout.split('\n').filter(name => /^Payload\/[^/]+\.app\/Info\.plist$/.test(name)).length !== 1) throw error('EIPA');
  } catch { throw error('EIPA'); }
}

export async function downloadSource({ url, output = 'input.ipa', expectedSize = 0,
  attempts = 4, budgetSeconds = 1200, transport = curlDownload, validate = validateIpa,
  sleep = ms => new Promise(resolveSleep => setTimeout(resolveSleep, ms)),
  log = console.error, now = Date.now, options = {} }) {
  let parsed;
  try {
    parsed = new URL(url);
    if ((parsed.protocol !== 'https:' && !(options.allowHttp && parsed.protocol === 'http:')) ||
        parsed.username || parsed.password || parsed.hash || /[\r\n]/.test(url)) throw error('EURL');
  } catch { throw error('EURL'); }
  expectedSize = Number(expectedSize);
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize > 4 * 1024 ** 3) throw error('ESIZE');
  const destination = resolve(output);
  const temporary = await mkdtemp(join(dirname(destination), '.ipa-download-'));
  const partial = join(temporary, 'source.part');
  const started = now();
  try {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const remaining = budgetSeconds - (now() - started) / 1000;
      if (remaining <= 0) throw error('EDEADLINE');
      // Deliberately restart on failure. Do not append to partial or stale
      // source content without a server-provided version/ETag guarantee.
      await rm(partial, { force: true });
      log(`Source download attempt ${attempt}/${attempts}; low-speed timeout 20s`);
      const result = await transport(parsed.href, partial, { ...options, maxSeconds: Math.min(options.maxSeconds || 900, remaining) });
      if (result.code === 0) {
        const size = (await stat(partial)).size;
        if (size <= 0 || (expectedSize && size !== expectedSize)) throw error('ESIZE');
        await validate(partial);
        await rename(partial, destination);
        const seconds = Math.max(0.001, (now() - started) / 1000);
        log(`Source IPA verified: ${size} bytes in ${seconds.toFixed(2)}s; avg ${(size / 1048576 / seconds).toFixed(2)} MiB/s`);
        return { size, seconds, attempts: attempt };
      }
      const retryable = retryableCurl(result.code, result.status);
      log(`Source download failed: curl=${result.code}; HTTP=${result.status}; ${retryable && attempt < attempts ? 'retrying from the beginning' : 'stopping'}`);
      if (!retryable || attempt === attempts) throw error('EDOWNLOAD');
      await sleep(1000 * 2 ** attempt);
    }
  } finally {
    // This is the exact mkdtemp directory created by this invocation.
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  downloadSource({ url: process.env.SOURCE_IPA_URL, expectedSize: process.env.SOURCE_IPA_SIZE || 0,
    output: process.argv[2] || 'input.ipa' }).catch(failure => {
    console.error('Source IPA download stopped: ' + (/^[A-Z]+$/.test(failure.code || '') ? failure.code : 'EDOWNLOAD'));
    process.exitCode = 1;
  });
}
