// Offline regression against the actual patched runtime; no account or network.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

if (!process.env.DSH_PREFIX) throw Error('Set DSH_PREFIX to the patched runtime');
const modules = join(resolve(process.env.DSH_PREFIX), 'node_modules');
const load = path => import(pathToFileURL(path));
const { Context } = await load(join(modules, '@deepseek-ai/cordis/lib/index.js'));
const { DeepSeekLlmApiExtensionRegistry: Registry } = await load(join(modules, '@deepseek-ai/dsh-deepseek-llm-api-extensions/lib/index.js'));
const { apply } = await load(join(modules, '@deepseek-ai/dsh-session-log-deepseek/lib/index.js'));

test('legacy enabled=true cannot register, read, prepare or acknowledge a session log', async () => {
  const ctx = new Context();
  const registry = new Registry(ctx);
  let reads = 0;
  apply({ deepseekLlmApiExtensions: registry, sessions: { get() { reads++; throw Error('private session accessed'); } } },
    { enabled: { get: () => true }, maxBytes: 8 * 1024 * 1024 });
  for (const purpose of ['agent', 'compaction', 'title']) {
    const prepared = await registry.prepare({ sessionId: 'synthetic-session', purpose, signal: new AbortController().signal });
    assert.deepEqual(Object.keys(prepared.fields), []);
    await prepared.accept();
  }
  assert.equal(reads, 0);
});

test('other extensions still prepare and acknowledge normally', async () => {
  const ctx = new Context();
  const registry = new Registry(ctx);
  let accepted = 0;
  const dispose = registry.register('synthetic_other', { prepare: async () => ({ value: { ok: true }, accept: () => accepted++ }) });
  const prepared = await registry.prepare({ signal: new AbortController().signal });
  assert.deepEqual(prepared.fields.synthetic_other, { ok: true });
  await prepared.accept();
  assert.equal(accepted, 1);
  dispose();
});

test('the real request serializer preserves model input and omits the blocked field', async () => {
  const lib = join(modules, '@deepseek-ai/dsh-llm-deepseek/lib');
  const file = join(lib, `privacy-test-${process.pid}.mjs`);
  try {
    await writeFile(file, await readFile(join(lib, 'index.js'), 'utf8') + '\nexport { prepareRequestExtensions };\n');
    const { prepareRequestExtensions } = await load(file);
    const registry = new Registry(new Context());
    let preparedLog = false;
    registry.register('dsh_session_log', { prepare: () => { preparedLog = true; return { value: { events: ['private'] } }; } });
    const input = { model: 'synthetic-model', messages: [{ role: 'user', content: 'normal model input' }], stream: true };
    const output = await prepareRequestExtensions(input, { signal: new AbortController().signal, sessionId: 'session' },
      request => registry.prepare(request), () => assert.fail('unexpected omission'), () => assert.fail('unexpected rejection'));
    assert.deepEqual(JSON.parse(output.payload), input);
    assert.equal(preparedLog, false);
    await output.accept();
  } finally {
    await unlink(file).catch(() => {});
  }
});
