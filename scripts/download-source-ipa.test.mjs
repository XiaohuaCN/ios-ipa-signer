import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { downloadSource, curlDownload, retryableCurl, validateIpa } from './download-source-ipa.mjs';

async function workspace(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'ipa-download-test-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
const url = 'https://storage.example/source.ipa?secret=never-log-this';
const noWait = async () => {};

test('retry connection reset without appending partial bytes; publish only verified file', () => workspace(async dir => {
  const output = join(dir, 'input.ipa'), logs = []; let attempts = 0, validated = 0;
  await writeFile(output, 'old');
  const result = await downloadSource({ url, output, expectedSize: 4, log: line => logs.push(line), sleep: noWait,
    transport: async (_, partial) => {
      assert.equal(await readFile(output, 'utf8'), 'old');
      assert.equal(await readFile(partial).catch(() => null), null);
      await writeFile(partial, ++attempts === 1 ? 'bad' : 'good');
      return { code: attempts === 1 ? 56 : 0, status: 200 };
    }, validate: async partial => { validated++; assert.equal(await readFile(partial, 'utf8'), 'good'); },
  });
  assert.equal(result.attempts, 2); assert.equal(validated, 1);
  assert.equal(await readFile(output, 'utf8'), 'good');
  assert.deepEqual(await readdir(dir), ['input.ipa']);
  assert.ok(!logs.join('\n').includes('secret')); assert.ok(!logs.join('\n').includes(url));
}));

test('auth/client/TLS errors do not retry; transient timeouts and server errors do', async () => {
  for (const code of [18, 28, 52, 56, 92]) assert.equal(retryableCurl(code, 200), true);
  for (const status of [408, 429, 500, 503]) assert.equal(retryableCurl(22, status), true);
  for (const status of [400, 401, 403, 404]) assert.equal(retryableCurl(22, status), false);
  assert.equal(retryableCurl(60, 0), false); assert.equal(retryableCurl(23, 200), false);
  await workspace(async dir => {
    let attempts = 0;
    await assert.rejects(downloadSource({ url, output: join(dir, 'out'), sleep: noWait, log: () => {},
      transport: async () => { attempts++; return { code: 22, status: 401 }; }, validate: async () => assert.fail(),
    }), { code: 'EDOWNLOAD' });
    assert.equal(attempts, 1); assert.deepEqual(await readdir(dir), []);
  });
});

test('attempts capped at four and all partial files removed on failure', () => workspace(async dir => {
  let count = 0;
  await assert.rejects(downloadSource({ url, output: join(dir, 'out'), sleep: noWait, log: () => {},
    transport: async (_, partial) => { count++; await writeFile(partial, 'partial'); return { code: 28, status: 0 }; },
  }), { code: 'EDOWNLOAD' });
  assert.equal(count, 4); assert.deepEqual(await readdir(dir), []);
}));

test('wrong size or invalid IPA cannot replace existing verified file', () => workspace(async dir => {
  const output = join(dir, 'out'); await writeFile(output, 'old');
  for (const expectedSize of [10, 3]) {
    await assert.rejects(downloadSource({ url, output, expectedSize, log: () => {}, sleep: noWait,
      transport: async (_, partial) => { await writeFile(partial, 'bad'); return { code: 0, status: 200 }; },
      validate: async () => { throw Object.assign(new Error('invalid'), { code: 'EIPA' }); },
    }), { code: expectedSize === 10 ? 'ESIZE' : 'EIPA' });
    assert.equal(await readFile(output, 'utf8'), 'old'); assert.deepEqual(await readdir(dir), ['out']);
  }
}));

test('URL restrictions and elapsed-time budget checked before network use', () => workspace(async dir => {
  const transport = async () => assert.fail('No network request expected');
  for (const value of ['http://example.test/a', 'https://u:p@example.test/a', 'https://example.test/a#secret', 'not a url']) {
    await assert.rejects(downloadSource({ url: value, output: join(dir, 'out'), transport }), { code: 'EURL' });
  }
  let time = 0;
  await assert.rejects(downloadSource({ url, output: join(dir, 'out'), budgetSeconds: 1,
    now: () => (time += 2000), transport }), { code: 'EDEADLINE' });
  assert.deepEqual(await readdir(dir), []);
}));

test('real curl follows redirects, stops low-speed responses and recovers partial reset', () => workspace(async dir => {
  let requests = 0;
  const server = createServer((req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { location: '/source' }); res.end(); return; }
    if (req.url === '/stall') { res.writeHead(200, { 'content-length': '4' }); res.write('x'); return; }
    if (++requests === 1) { res.writeHead(200, { 'content-length': '10000' }); res.end('x'); }
    else { res.writeHead(200, { 'content-length': '4' }); res.end('good'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const root = 'http://127.0.0.1:' + server.address().port;
  try {
    const result = await downloadSource({ url: root + '/redirect', output: join(dir, 'out'), expectedSize: 4,
      options: { allowHttp: true, idleSeconds: 1, maxSeconds: 3 }, sleep: noWait, log: () => {}, validate: async () => {},
    });
    assert.equal(result.attempts, 2); assert.equal(await readFile(join(dir, 'out'), 'utf8'), 'good');
    const stalled = await curlDownload(root + '/stall', join(dir, 'stall'), { allowHttp: true, idleSeconds: 1, maxSeconds: 3 });
    assert.equal(stalled.code, 28);
    await writeFile(join(dir, 'invalid.ipa'), '<html>error</html>');
    await assert.rejects(validateIpa(join(dir, 'invalid.ipa')), { code: 'EIPA' });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}));
