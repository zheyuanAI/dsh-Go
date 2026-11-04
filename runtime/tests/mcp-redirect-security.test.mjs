// Exercise the SDK resolved by the engine's MCP plugin, with loopback servers only.
// DSH_PREFIX=<installed runtime prefix> node --test runtime/tests/mcp-redirect-security.test.mjs
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import test from 'node:test';

if (!process.env.DSH_PREFIX) throw new Error('Set DSH_PREFIX to an installed runtime prefix');
const require = createRequire(join(resolve(process.env.DSH_PREFIX), 'node_modules/@deepseek-ai/dsh-mcp-client/lib/index.js'));
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/client');

async function server(t, handler) {
  const instance = createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  t.after(async () => {
    instance.closeAllConnections();
    await new Promise((done, reject) => instance.close(error => error ? reject(error) : done()));
  });
  return `http://127.0.0.1:${instance.address().port}`;
}

for (const status of [301, 302, 303, 307, 308]) {
  test(`MCP refuses cross-origin ${status} before disclosing headers or body`, async t => {
    const received = [];
    const target = await server(t, async (req, res) => {
      let body = '';
      for await (const part of req) body += part;
      received.push({ headers: req.headers, body });
      res.writeHead(202).end();
    });
    const origin = await server(t, (req, res) => {
      req.resume();
      res.writeHead(status, { Location: `${target}/capture` }).end();
    });
    const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), {
      requestInit: { headers: { 'X-API-Key': 'test-only-marker' } },
      sessionId: 'test-only-session',
    });
    await transport.start();
    t.after(() => transport.close());
    await assert.rejects(transport.send(
      { jsonrpc: '2.0', method: 'notifications/test', params: { marker: 'test-only-body' } },
      { requestSignal: AbortSignal.timeout(3000) },
    ));
    assert.deepEqual(received, [], 'redirect target must receive no request at all');
  });
}

test('MCP still delivers a POST through a same-origin redirect', async t => {
  let delivered;
  const origin = await server(t, async (req, res) => {
    if (req.url === '/mcp') {
      req.resume();
      res.writeHead(307, { Location: '/final' }).end();
      return;
    }
    let body = '';
    for await (const part of req) body += part;
    delivered = { method: req.method, key: req.headers['x-api-key'], body: JSON.parse(body) };
    res.writeHead(202).end();
  });
  const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), {
    requestInit: { headers: { 'X-API-Key': 'test-only-marker' } },
  });
  await transport.start();
  t.after(() => transport.close());
  const message = { jsonrpc: '2.0', method: 'notifications/test' };
  await transport.send(message, { requestSignal: AbortSignal.timeout(3000) });
  assert.deepEqual(delivered, { method: 'POST', key: 'test-only-marker', body: message });
});
