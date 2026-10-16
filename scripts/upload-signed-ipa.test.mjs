import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createTransport, uploadParts, uploadOssFile, curlPut } from './upload-signed-ipa.mjs';
import { parseCurlProgress, createTransferProgress } from './transfer-progress.mjs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('progress parser accepts numeric meters only, using the correct transfer direction', () => {
  const row = ' 50 4M 25 1M 50 2M 1M 2M 0:00:04 0:00:02 0:00:02 512k';
  assert.equal(parseCurlProgress(row, 'upload').transferred, 2 * 1048576);
  assert.equal(parseCurlProgress(row, 'download').transferred, 1048576);
  for (const raw of ['curl: (22) private-url?Signature=private-token', '::warning::secret', 'Set-Cookie: secret',
    row.replace('512k', 'https://secret.example'), row.replace('0:00:02', 'secret'), 'x'.repeat(2000) + row]) {
    assert.equal(parseCurlProgress(raw, 'upload'), null);
  }
});
test('progress output is throttled, handles split rows and never forwards raw diagnostics', () => {
  const logs = []; let time = 0;
  const progress = createTransferProgress('upload', { total: 4 * 1048576, log: s => logs.push(s), now: () => time });
  const row = '50 4M 0 0 50 2M 0 1M 0:00:04 0:00:02 0:00:02 1M';
  progress.push('curl: private-url?Signature=secret\n::warning::private-token\r');
  progress.push(row.slice(0, 22)); progress.push(row.slice(22) + '\r');
  time = 1000; progress.push(row + '\r'); assert.equal(logs.length, 1);
  time = 5000; progress.push(row + '\r'); assert.equal(logs.length, 2);
  progress.push('100 4M 0 0 100 4M 0 1M 0:00:04 0:00:04 --:--:-- 1M'); progress.end();
  assert.equal(logs.length, 3); assert.match(logs[0], /^OSS upload: 50% \| 2.00\/4.00 MiB/);
  assert.match(logs[2], /^OSS upload: 100%/); assert.ok(!logs.join('\n').includes('secret'));
});
test('real curl upload produces safe progress while stdout stays machine-readable', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ipa-upload-progress-'));
  const file = join(dir, 'signed.ipa'), logs = [];
  const bytes = Buffer.alloc(256 * 1024, 7); await writeFile(file, bytes);
  let received = 0;
  const server = http.createServer((req, res) => {
    req.on('data', chunk => { received += chunk.length; });
    req.on('end', () => setTimeout(() => res.end('ok'), 1200));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await curlPut({ file, url: 'http://127.0.0.1:' + server.address().port + '/private?Signature=secret',
      deadlineMs: 10000, size: bytes.length, allowHttp: true, log: s => logs.push(s), progressIntervalMs: 0 });
    assert.equal(result.status, 200); assert.equal(result.bytes, bytes.length); assert.equal(received, bytes.length);
    assert.ok(logs.some(s => s.startsWith('OSS upload: 100%'))); assert.ok(!logs.join('\n').includes('Signature'));
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(dir, { recursive: true, force: true }); }
});

const session = {
  upload_id: 'local-session', chunk_size: 8, total_chunks: 3,
  direct_upload_url: 'https://relay.example/fs/multipart/chunk',
  direct_upload_token: 'secret-token', direct_remote_upload_id: 'remote-session',
  direct_resume_token: 'resume-0',
};
const response = data => ({ status: 200, text: JSON.stringify({ code: 200, data }) });
const noWait = async () => {};
const oss = {
  storage: 'oss', upload_url: 'https://private-bucket.oss-accelerate.aliyuncs.com/ipa/XY/signed.ipa?Signature=private-secret',
  upload_headers: { 'Content-Type': 'application/octet-stream' },
  signed_ipa_url: 'https://private-bucket.oss-cn-hangzhou.aliyuncs.com/ipa/XY/signed.ipa',
};
test('OSS upload streams one file directly and retains the original public download host', async () => {
  const logs = [], calls = [];
  const result = await uploadOssFile({ file: 'signed.ipa', size: 512, ticket: oss, log: line => logs.push(line),
    getTicket: () => assert.fail('No unnecessary refresh'), put: async options => { calls.push(options); return { status: 200, bytes: 512 }; },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].file, 'signed.ipa');
  assert.equal(calls[0].url, oss.upload_url);
  assert.equal(result, oss.signed_ipa_url);
  assert.equal(logs[0], 'Upload route: direct OSS (transfer acceleration)');
  assert.ok(!logs[0].includes('OpenList'));
  assert.ok(!logs.filter(line => !line.startsWith('::add-mask::')).join('\n').includes('private-bucket'));
});
test('regional OSS route is identified without exposing storage addresses', async () => {
  const ticket = { ...oss, upload_url: oss.upload_url.replace('.oss-accelerate.', '.oss-cn-hangzhou.') };
  const logs = [];
  await uploadOssFile({ file: 'signed.ipa', size: 512, ticket, log: line => logs.push(line),
    getTicket: () => assert.fail('Unexpected refresh'), put: async () => ({ status: 200, bytes: 512 }) });
  assert.equal(logs[0], 'Upload route: direct OSS (regional endpoint)');
});
test('expired OSS credentials refresh before retry; storage response contents stay private', async () => {
  let uploads = 0, refreshes = 0;
  const refreshed = { ...oss, upload_url: oss.upload_url.replace('private-secret', 'fresh-secret') };
  await uploadOssFile({ file: 'signed.ipa', size: 512, ticket: oss, log: () => {}, sleep: noWait,
    getTicket: async () => { refreshes++; return refreshed; },
    put: async options => { if (++uploads === 1) return { status: 403, bytes: 0 }; assert.equal(options.url, refreshed.upload_url); return { status: 200, bytes: 512 }; },
  });
  assert.equal(uploads, 2); assert.equal(refreshes, 1);
});
test('OSS endpoints cannot redirect private data to an arbitrary host or return a different object', async () => {
  for (const ticket of [{ ...oss, upload_url: 'https://attacker.example/file' }, { ...oss, signed_ipa_url: oss.signed_ipa_url + 'wrong' }]) {
    await assert.rejects(uploadOssFile({ file: 'signed.ipa', size: 512, ticket, log: () => {}, put: () => assert.fail() }), error => error.code === 'EPROTOCOL');
  }
});
test('incomplete OSS transfers and redirects never publish a successful output', async () => {
  for (const reply of [{ status: 200, bytes: 511 }, { status: 302, bytes: 512 }]) {
    await assert.rejects(uploadOssFile({ file: 'signed.ipa', size: 512, ticket: oss, log: () => {}, put: async () => reply }));
  }
});

test('Cloudflare relay uploads ordered bytes using the latest resume token', async () => {
  const input = Buffer.from('12345678901234567890'), calls = [], logs = [];
  const transport = { stats: { requests: 3, reused: 2 }, request: async (url, options) => {
    const index = calls.length;
    assert.equal(url, session.direct_upload_url);
    assert.equal(options.headers['x-upload-session'], 'resume-' + index);
    assert.equal(options.headers['x-chunk-index'], String(index));
    assert.equal(options.deadlineMs, 180000);
    assert.equal(options.idleTimeoutMs, 120000);
    assert.deepEqual(options.body, input.subarray(index * 8, index * 8 + 8));
    calls.push(index);
    return response({ resume_token: 'resume-' + (index + 1) });
  } };
  const result = await uploadParts({ session, size: input.length, transport, log: line => logs.push(line), sleep: noWait,
    readPart: async (offset, length) => input.subarray(offset, offset + length),
    servicePost: async (path, body, headers) => {
      assert.equal(path, '/api/signing/multipart/complete');
      assert.equal(headers['x-openlist-upload-session'], 'resume-3');
      return { signed_ipa_url: 'https://download.example/signed.ipa' };
    },
  });
  assert.deepEqual(calls, [0, 1, 2]);
  assert.equal(result, 'https://download.example/signed.ipa');
  assert.ok(!logs.filter(line => !line.startsWith('::add-mask::')).join('\n').includes('secret-token'));
});

test('a stalled relay retries the same bytes without contacting the provider directly', async () => {
  let requests = 0;
  const logs = [];
  await uploadParts({ session: { ...session, total_chunks: 1 }, size: 4,
    transport: { stats: {}, request: async (url, options) => {
      assert.equal(url, session.direct_upload_url);
      assert.deepEqual(options.body, Buffer.from('1234'));
      assert.equal(options.headers['x-upload-session'], 'resume-0');
      if (++requests === 1) throw Object.assign(new Error('private URL and token'), { code: 'ESTALLED' });
      return response({ resume_token: 'resume-1' });
    } },
    log: line => logs.push(line), sleep: noWait, readPart: async () => Buffer.from('1234'),
    servicePost: async () => ({ signed_ipa_url: 'https://download.example/signed.ipa' }),
  });
  assert.equal(requests, 2);
  assert.ok(!logs.join('\n').includes('private URL'));
});

test('auth failure stops without retries or a route bypass', async () => {
  let requests = 0;
  await assert.rejects(uploadParts({ session: { ...session, total_chunks: 1 }, size: 4,
    transport: { stats: {}, request: async () => { requests++; return { status: 401, text: 'secret' }; } },
    log: () => {}, sleep: noWait, readPart: async () => Buffer.from('1234'), servicePost: async () => assert.fail(),
  }), error => error.code === 'HTTP_401');
  assert.equal(requests, 1);
});

test('upload budget bounds attempts and never publishes an incomplete file', async () => {
  let time = 0, requests = 0;
  await assert.rejects(uploadParts({ session: { ...session, total_chunks: 1 }, size: 4, budgetMs: 50, now: () => time,
    transport: { stats: {}, request: async (_url, options) => {
      requests++;
      assert.equal(options.deadlineMs, 50);
      time = 50;
      throw Object.assign(new Error('timed out'), { code: 'EDEADLINE' });
    } },
    log: () => {}, sleep: noWait, readPart: async () => Buffer.from('1234'), servicePost: async () => assert.fail(),
  }), error => error.code === 'EUPLOADDEADLINE');
  assert.equal(requests, 1);
});

test('bad sizes and unsafe endpoints fail before transmitting credentials', async () => {
  const args = { session, size: 20, transport: { stats: {}, request: async () => assert.fail() }, log: () => {}, readPart: async () => assert.fail() };
  await assert.rejects(uploadParts({ ...args, session: { ...session, total_chunks: 4 } }), error => error.code === 'EPROTOCOL');
  await assert.rejects(uploadParts({ ...args, session: { ...session, direct_upload_url: 'http://relay.example' } }), error => error.code === 'EPROTOCOL');
});

test('transport reuses a connection, rejects redirects and detects a stalled response', async () => {
  let connections = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    if (req.url === '/stall') return;
    if (req.url === '/redirect') { res.writeHead(302, { location: '/secret' }); res.end(); return; }
    res.end('{"ok":true}');
  });
  server.on('connection', () => connections++);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const transport = createTransport({ allowHttp: true, connectMs: 1000, idleMs: 70, totalMs: 1000 });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await transport.request(base + '/ok', { body: 'test' })).status, 200);
    assert.equal(connections, 1);
    assert.equal(transport.stats.reused, 2);
    assert.equal((await transport.request(base + '/redirect')).status, 302);
    const started = Date.now();
    await assert.rejects(transport.request(base + '/stall'), error => error.code === 'ESTALLED');
    assert.ok(Date.now() - started < 700);
  } finally {
    transport.close(); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('request deadline applies even with periodic response data', async () => {
  const server = http.createServer((req, res) => {
    req.resume(); res.writeHead(200);
    const timer = setInterval(() => res.write(' '), 15);
    res.on('close', () => clearInterval(timer));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const transport = createTransport({ allowHttp: true, connectMs: 1000, idleMs: 100, totalMs: 120 });
  try {
    await assert.rejects(transport.request('http://127.0.0.1:' + server.address().port), error => error.code === 'EDEADLINE');
  } finally {
    transport.close(); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
