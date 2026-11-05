// Explicit live smoke check, using only synthetic data and deleting its share.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

const origin = process.argv[2];
if (!origin || new URL(origin).protocol !== 'https:') throw Error('Pass the HTTPS Site origin');
const request = (path, init = {}) => fetch(origin + path, { ...init, redirect: 'error', signal: AbortSignal.timeout(15000) });
const health = await (await request('/api/health')).json();
assert.equal(health.service, 'dsh-go-services');
assert.equal(health.sharing, true);
assert.equal(health.usage, true);
const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const plain = new TextEncoder().encode('DSH Go synthetic service test. No user conversation.');
const encrypted = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
const blob = new Uint8Array(16 + encrypted.length);
blob.set([68, 83, 71, 49]); blob.set(iv, 4); blob.set(encrypted, 16);
const created = await request('/api/v1/c?ttl=7d', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: blob });
assert.equal(created.status, 201);
const { id, deleteToken } = await created.json();
try {
  const response = await request('/api/v1/c/' + id);
  assert.equal(response.status, 200);
  const returned = new Uint8Array(await response.arrayBuffer());
  assert.deepEqual(returned, blob);
  const opened = new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: returned.slice(4, 16) }, key, returned.slice(16)));
  assert.deepEqual(opened, plain);
  const viewer = await request('/c/' + id);
  assert.equal(viewer.status, 200);
  assert.ok((await viewer.text()).includes('dshgo://'));
  const invalidUsage = await request('/api/usage/v1', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"text":"synthetic invalid report"}' });
  assert.equal(invalidUsage.status, 400);
} finally {
  const removed = await request('/api/v1/c/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + deleteToken } });
  assert.ok([204, 404].includes(removed.status));
}
assert.equal((await request('/api/v1/c/' + id)).status, 404);
console.log('Public health, encrypted upload/read/decrypt, viewer, usage validation and deletion passed.');
