import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createTransport, uploadParts, withRetry } from './upload-signed-ipa.mjs';

const session = {
  upload_id: 'local-session', chunk_size: 8, total_chunks: 3,
  direct_upload_url: 'https://relay.example/fs/multipart/chunk',
  direct_upload_token: 'secret-token', direct_remote_upload_id: 'remote-session',
  direct_resume_token: 'resume-0',
  direct_part_urls_url: 'https://relay.example/fs/multipart/part-urls',
  direct_ack_url: 'https://relay.example/fs/multipart/ack',
};
const response = data => ({ status: 200, text: JSON.stringify({ code: 200, data }) });
const noWait = async () => {};

test('relay first, sequential bytes, latest resume passed to next part and completion', async () => {
  const input = Buffer.from('12345678901234567890'), calls = [], logs = [];
  const transport = { stats: { requests: 3, reused: 2 }, request: async (url, options) => {
    const index = Number(options.headers['x-chunk-index']);
    assert.equal(url, session.direct_upload_url);
    assert.equal(options.headers['x-upload-session'], 'resume-' + index);
    assert.deepEqual(options.body, input.subarray(index * 8, index * 8 + 8));
    calls.push(index);
    return response({ resume_token: 'resume-' + (index + 1) });
  } };
  const result = await uploadParts({ session, size: input.length, transport, log: text => logs.push(text), sleep: noWait,
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

test('transient failure retries the same bytes and continuation, not next part', async () => {
  let attempts = 0, completed = false;
  const transport = { stats: { requests: 2, reused: 0 }, request: async (_url, options) => {
    assert.equal(options.headers['x-chunk-index'], '0');
    assert.equal(options.headers['x-upload-session'], 'resume-0');
    if (++attempts === 1) throw Object.assign(new Error('private URL and token'), { code: 'ESTALLED' });
    return response({ resume_token: 'resume-1' });
  } };
  const logs = [];
  await uploadParts({ session: { ...session, total_chunks: 1 }, size: 4, transport,
    log: line => logs.push(line), sleep: noWait, readPart: async () => Buffer.from('1234'),
    servicePost: async () => { completed = true; return { signed_ipa_url: 'https://download.example/signed.ipa' }; },
  });
  assert.equal(attempts, 2);
  assert.equal(completed, true);
  assert.ok(!logs.join('\n').includes('private URL'));
});

test('auth failure is not retried or bypassed via direct upload', async () => {
  let requests = 0;
  await assert.rejects(uploadParts({ session: { ...session, total_chunks: 1 }, size: 4,
    transport: { stats: {}, request: async () => { requests++; return { status: 401, text: 'secret' }; } },
    log: () => {}, sleep: noWait, readPart: async () => Buffer.from('1234'), servicePost: async () => assert.fail(),
  }), error => error.code === 'HTTP_401');
  assert.equal(requests, 1);
});

test('one capped alternate route uses current resume and omits provider Content-Type', async () => {
  const calls = [];
  const transport = { stats: {}, request: async (url, options) => {
    calls.push(url);
    if (url === session.direct_upload_url) return { status: 503, text: '' };
    if (url === session.direct_part_urls_url) {
      assert.equal(options.headers['x-upload-session'], 'resume-0');
      return response({ parts: [{ index: 0, upload_url: 'https://provider.example/part?signed=secret' }] });
    }
    if (url.startsWith('https://provider.example')) {
      assert.equal(options.deadlineMs, 10000);
      assert.equal(options.headers, undefined);
      return { status: 200, text: '' };
    }
    if (url === session.direct_ack_url) return response({ resume_token: 'resume-1' });
    assert.fail();
  } };
  await uploadParts({ session: { ...session, total_chunks: 1 }, size: 4, transport,
    log: () => {}, sleep: noWait, readPart: async () => Buffer.from('1234'),
    servicePost: async () => ({ signed_ipa_url: 'https://download.example/signed.ipa' }),
  });
  assert.equal(calls.filter(url => url === session.direct_upload_url).length, 3);
  assert.equal(calls.filter(url => url.startsWith('https://provider.example')).length, 1);
});

test('bad sizes and unsafe endpoint protocols fail before transmitting credentials', async () => {
  const args = { session, size: 20, transport: { stats: {}, request: async () => assert.fail() }, log: () => {}, readPart: async () => assert.fail() };
  await assert.rejects(uploadParts({ ...args, session: { ...session, total_chunks: 4 } }), error => error.code === 'EPROTOCOL');
  await assert.rejects(uploadParts({ ...args, session: { ...session, direct_upload_url: 'http://relay.example' } }), error => error.code === 'EPROTOCOL');
});

test('transport reuses a connection, does not follow redirects, detects no-progress stall', async () => {
  let connections = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    if (req.url === '/stall') return;
    if (req.url === '/redirect') { res.writeHead(302, { location: '/secret' }); res.end(); return; }
    res.setHeader('content-type', 'application/json');
    res.end('{"ok":true}');
  });
  server.on('connection', () => connections++);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
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
    transport.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('request hard cap remains effective even with periodic response data', async () => {
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200);
    const timer = setInterval(() => res.write(' '), 15);
    res.on('close', () => clearInterval(timer));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const transport = createTransport({ allowHttp: true, connectMs: 1000, idleMs: 100, totalMs: 120 });
  try {
    await assert.rejects(transport.request(`http://127.0.0.1:${server.address().port}`), error => error.code === 'EDEADLINE');
  } finally {
    transport.close(); server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
