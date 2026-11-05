import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const temp = mkdtempSync(resolve(tmpdir(), 'dsh-sites-'));
const output = resolve(temp, 'worker.mjs');
execFileSync(process.execPath, [resolve(here, '../scripts/build-sites.mjs'), output]);
const { default: worker } = await import(pathToFileURL(output));
rmSync(temp, { recursive: true });

class MemoryBucket {
  objects = new Map();
  revision = 0;
  async head(key) { return this.objects.get(key) ?? null; }
  async get(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    return { ...object, body: new Blob([object.bytes]).stream(), text: async () => new TextDecoder().decode(object.bytes) };
  }
  async put(key, value, options = {}) {
    const previous = this.objects.get(key);
    if (options.onlyIf?.etagDoesNotMatch === '*' && previous) return null;
    if (options.onlyIf?.etagMatches && previous?.etag !== options.onlyIf.etagMatches) return null;
    const object = { key, bytes: typeof value === 'string' ? new TextEncoder().encode(value) : value,
      etag: String(++this.revision), uploaded: new Date(), customMetadata: options.customMetadata ?? {},
      size: typeof value === 'string' ? Buffer.byteLength(value) : value.byteLength };
    this.objects.set(key, object);
    return object;
  }
  async delete(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) this.objects.delete(key); }
  async list({ prefix, limit }) { return { objects: [...this.objects.values()].filter(o => o.key.startsWith(prefix)).slice(0, limit) }; }
}

function server() {
  const env = { BUCKET: new MemoryBucket(), USAGE_SECRET: 'synthetic-test-secret' };
  const pending = [];
  const fetch = async (path, options = {}) => worker.fetch(new Request('https://site.example' + path, options), env,
    { waitUntil: p => pending.push(p) });
  return { env, fetch, finish: () => Promise.all(pending) };
}
const blob = new Uint8Array(40); blob.set([68, 83, 71, 49]);
const uploadOptions = { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: blob };

test('health requires configured storage and secret; login HTML is never returned', async () => {
  const s = server();
  assert.deepEqual(await (await s.fetch('/api/health')).json(), { service: 'dsh-go-services', v: 1, sharing: true, usage: true });
  delete s.env.USAGE_SECRET;
  assert.equal((await s.fetch('/api/health')).status, 503);
});
test('encrypted upload round trip, deletion capability and repeated deletion', async () => {
  const s = server();
  const response = await s.fetch('/api/v1/c?ttl=7d', uploadOptions);
  assert.equal(response.status, 201);
  const { id, deleteToken, expiresAt } = await response.json();
  assert.ok(expiresAt);
  const fetched = await s.fetch('/api/v1/c/' + id);
  assert.deepEqual(new Uint8Array(await fetched.arrayBuffer()), blob);
  assert.equal((await s.fetch('/api/v1/c/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + 'x'.repeat(43) } })).status, 403);
  assert.equal((await s.fetch('/api/v1/c/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + deleteToken } })).status, 204);
  assert.equal((await s.fetch('/api/v1/c/' + id)).status, 404);
  await s.finish();
});
test('malformed, oversized and rate-limited uploads are rejected', async () => {
  const s = server();
  assert.equal((await s.fetch('/api/v1/c?ttl=invalid', uploadOptions)).status, 400);
  assert.equal((await s.fetch('/api/v1/c', { ...uploadOptions, body: new Uint8Array(40) })).status, 400);
  assert.equal((await s.fetch('/api/v1/c', { ...uploadOptions, headers: { ...uploadOptions.headers, 'Content-Length': '20971521' } })).status, 413);
  const statuses = [];
  for (let i = 0; i < 6; i++) statuses.push((await s.fetch('/api/v1/c', uploadOptions)).status);
  assert.ok(statuses.includes(429));
  await s.finish();
});
test('expired ciphertext is unreadable and is cleaned up', async () => {
  const s = server();
  const { id } = await (await s.fetch('/api/v1/c?ttl=7d', uploadOptions)).json();
  const object = [...s.env.BUCKET.objects.values()].find(o => o.key.endsWith(id));
  object.uploaded = new Date(Date.now() - 8 * 86400000);
  assert.equal((await s.fetch('/api/v1/c/' + id)).status, 404);
  await s.finish();
  assert.ok(!s.env.BUCKET.objects.has(object.key));
});
test('usage is validated, pseudonymized, deduplicated and has no public read route', async () => {
  const s = server();
  const report = { v: 1, iid: 'A'.repeat(22), day: new Date(Date.now() + 8 * 3600000).toISOString().slice(0, 10),
    app: '1.0.10-local', build: 11050929, sdk: 35, abi: 'arm64-v8a', maker: 'test', lang: 'zh', engine: 'proot',
    counts: { turns: 1, voice: 0, phone: 0, share: 0, gen: 0, plugins: 0 } };
  const send = body => s.fetch('/api/usage/v1', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await send(report)).status, 204);
  assert.equal((await send(report)).status, 204);
  const stored = [...s.env.BUCKET.objects.values()].filter(o => o.key.startsWith('usage/'));
  assert.equal(stored.length, 1);
  assert.ok(!new TextDecoder().decode(stored[0].bytes).includes(report.iid));
  assert.equal((await send({ ...report, text: 'private conversation' })).status, 400);
  assert.equal((await s.fetch('/api/usage/v1')).status, 405);
  assert.equal((await s.fetch('/usage/' + stored[0].key)).status, 404);
  await s.finish();
});
test('browser viewer CSP matches its actual inline script after moving repository links', async () => {
  const s = server();
  const page = await (await s.fetch('/c/0123456789')).text();
  const script = /<script>([\s\S]*?)<\/script>/.exec(page)[1];
  const hash = createHash('sha256').update(script).digest('base64');
  assert.ok(page.includes('sha256-' + hash));
  assert.ok(page.includes('zheyuanAI/dsh-Go'));
  assert.ok(!page.includes('ccch1mneyyy/dsh-go'));
});
