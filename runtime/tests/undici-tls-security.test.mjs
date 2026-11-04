// Verify that Agent preserves application-supplied TLS identity checks.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import test from 'node:test';

if (!process.env.DSH_PREFIX) throw new Error('Set DSH_PREFIX to an installed runtime prefix');
const prefix = resolve(process.env.DSH_PREFIX);

for (const caller of ['dsh-http-proxy', 'dsh-web-fetch-http']) {
  test(`${caller}: Agent forwards the custom TLS validator to its connection pool`, async t => {
    const require = createRequire(join(prefix, `node_modules/@deepseek-ai/${caller}/lib/index.js`));
    const { Agent, Pool, request } = require('undici');
    const server = createServer((req, res) => res.end('ok'));
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async () => {
      server.closeAllConnections();
      await new Promise(done => server.close(done));
    });
    const checkServerIdentity = () => new Error('test-only identity rejection');
    let pools = 0;
    const agent = new Agent({
      tls: { checkServerIdentity },
      factory(origin, options) {
        assert.equal(options.tls?.checkServerIdentity, checkServerIdentity,
          'TLS callback must survive Agent option cloning');
        pools++;
        return new Pool(origin, options);
      },
    });
    t.after(() => agent.close());
    const response = await request(`http://127.0.0.1:${server.address().port}`, { dispatcher: agent });
    assert.equal(await response.body.text(), 'ok');
    assert.equal(pools, 1);
  });
}
