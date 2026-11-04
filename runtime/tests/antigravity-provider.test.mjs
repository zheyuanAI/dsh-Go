// SPDX-License-Identifier: MIT
// Actual patched runtime, synthetic credentials, injected transport; no live account.
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

if (!process.env.DSH_PREFIX) throw Error('Set DSH_PREFIX to a patched runtime');
const lib = join(resolve(process.env.DSH_PREFIX), 'node_modules/@deepseek-ai/dsh-llm-pi-ai/lib');
const load = path => import(pathToFileURL(path));
const { antigravityProvider, antigravityModels, callbackCode, requestEnvelope, readFrames, PROVIDER_ID } = await load(join(lib, 'dsh-go-antigravity.mjs'));
const piRoot = join(resolve(process.env.DSH_PREFIX), 'node_modules/@earendil-works/pi-ai/dist');
const { normalizeContext } = await load(join(piRoot, 'utils/transcript.js'));
const model = antigravityModels().find(m => m.id.includes('3.8-flash'));
const key = 'SYNTHETIC_ACCESS_NOT_A_REAL_TOKEN';
const grant = { type: 'oauth', access: key, refresh: 'SYNTHETIC_REFRESH|synthetic-project', expires: Date.now() + 3600000 };
const callback = state => `http://localhost:51121/oauth-callback?code=synthetic-code&state=${state}`;
const context = (extra = {}) => normalizeContext({ systemPrompt: 'System instruction',
  messages: [{ role: 'user', content: 'hello', timestamp: 0 }], ...extra });
const streamResponse = frames => new Response(frames.map(f => `data: ${JSON.stringify({ response: f })}\r\n\r\n`).join(''), { headers: { 'Content-Type': 'text/event-stream' } });
const stop = { candidates: [{ content: { parts: [{ text: '完成' }] }, finishReason: 'STOP' }] };

test('patched DSH catalog resolves a subscription profile and preserves existing providers', async () => {
  // Export private helpers from an isolated sibling copy of the actual patched package.
  const file = join(lib, `antigravity-test-${process.pid}.mjs`);
  try {
    const source = await readFile(join(lib, 'index.js'), 'utf8');
    await writeFile(file, source + '\nexport { resolveProfiles, catalogProviders };\n');
    const { resolveProfiles, PiAiAdapter, catalogProviders } = await load(file);
    const sent = [];
    catalogProviders().set(PROVIDER_ID, antigravityProvider({ transport: async (_url, init) => {
      sent.push(JSON.parse(init.body));
      return streamResponse(sent.length > 1 ? [stop] : [{ candidates: [{ content: { parts: [
        { functionCall: { name: 'lookup', args: { q: 'hello' } }, thoughtSignature: 'c3ludGhldGljLXNpZw==' },
      ] }, finishReason: 'STOP' }] }]);
    } }));
    const profiles = resolveProfiles({ [PROVIDER_ID]: { displayName: 'Antigravity' }, 'openai-codex': {} });
    const adapter = new PiAiAdapter({ profiles: () => profiles, resolveApiKey: async () => undefined,
      auth: { credentials: { read: async id => id === PROVIDER_ID ? grant : undefined, list: async () => [],
        modify: async (_id, fn) => fn(grant), delete: async () => {} },
        authContext: { env: async () => undefined, fileExists: async () => false } } });
    const models = await adapter.listModels(PROVIDER_ID);
    assert(models.length >= 3);
    assert(models.some(m => (m.model ?? m.id) === model.id));
    assert(profiles.has('openai-codex'));
    assert(models.every(m => !String(m.model ?? m.id).includes('image')));
    const user = { role: 'user', content: [{ type: 'text', text: 'hello' }] };
    const request = { provider: PROVIDER_ID, model: model.id, messages: [user], sessionId: 'synthetic-session',
      tools: [{ name: 'lookup', description: 'Lookup', parameters: { type: 'object', properties: { q: { type: 'string' } } } }] };
    const first = [];
    for await (const chunk of adapter.stream(request)) first.push(chunk);
    const finish = first.find(c => c.type === 'finish');
    assert.equal(finish.reason.kind, 'tool-calls', JSON.stringify(finish));
    const blocks = first.filter(c => c.type === 'block-end').map(c => c.block);
    const call = blocks.find(b => b.type === 'tool-call');
    assert.equal(JSON.parse(call.arguments).q, 'hello');
    const assistant = { id: 'assistant-1', role: 'assistant', content: blocks,
      source: { kind: 'model', provider: PROVIDER_ID, model: model.id, replayState: finish.replayState } };
    const tool = { id: 'tool-1', role: 'tool', toolCallId: call.id,
      source: { kind: 'tool', callId: call.id }, content: [{ type: 'text', text: 'found' }] };
    const second = [];
    for await (const chunk of adapter.stream({ ...request, messages: [user, assistant, tool] })) second.push(chunk);
    assert.equal(second.find(c => c.type === 'finish').reason.kind, 'stop');
    assert(second.some(c => c.type === 'text-delta' && c.text === '完成'));
    const replayCall = sent[1].request.contents.flatMap(c => c.parts).find(p => p.functionCall);
    assert.equal(replayCall.thoughtSignature, 'c3ludGhldGljLXNpZw==');
    assert.equal(replayCall.functionCall.id, call.id);
    assert(sent[1].request.contents.some(c => c.parts.some(p => p.functionResponse?.id === call.id)));
  } finally { await unlink(file).catch(() => {}); }
});

test('full callback origin, path, state and singleton parameters are required', () => {
  assert.equal(callbackCode(callback('expected'), 'expected'), 'synthetic-code');
  for (const bad of ['synthetic-code', callback('wrong'), callback('expected') + '&code=duplicate',
    callback('expected').replace('localhost', 'attacker.invalid'), callback('expected').replace('oauth-callback', 'elsewhere'),
    callback('expected') + '&state=expected']) {
    assert.throws(() => callbackCode(bad, 'expected'), /state mismatch/);
  }
});

test('login exchanges only its own callback and returns the existing OAuth grant shape', async () => {
  let calls = 0;
  const provider = antigravityProvider({ authorize: async () => ({ url: 'https://accounts.google.com/o/oauth2/v2/auth?state=expected' }),
    exchange: async (code, state, options) => { calls++; assert.equal(code, 'synthetic-code'); assert.equal(state, 'expected'); assert(options.signal); return { ...grant, type: 'success' }; } });
  const signal = new AbortController().signal;
  const events = [];
  const interaction = { signal, notify: e => events.push(e), prompt: async () => callback('expected') };
  assert.deepEqual(await provider.auth.oauth.login(interaction), grant);
  assert.equal(events[0].type, 'auth_url');
  await assert.rejects(provider.auth.oauth.login({ ...interaction, prompt: async () => callback('wrong') }), /state mismatch/);
  assert.equal(calls, 1);
});

test('cancelling a pending pasted callback never exchanges or stores a token', async () => {
  const controller = new AbortController();
  let exchanged = false;
  const provider = antigravityProvider({ authorize: async () => ({ url: 'https://accounts.google.com/auth?state=x' }),
    exchange: async () => { exchanged = true; } });
  await assert.rejects(provider.auth.oauth.login({ signal: controller.signal, notify() {}, prompt: async () => {
    controller.abort(); return callback('x');
  } }));
  assert.equal(exchanged, false);
});

test('refresh preserves project context; request auth never includes the refresh token', async () => {
  const provider = antigravityProvider({ refresh: async token => { assert.equal(token, 'SYNTHETIC_REFRESH');
    return { access: 'SYNTHETIC_NEW_ACCESS', refresh: 'SYNTHETIC_NEW_REFRESH', expires: grant.expires + 1 }; } });
  const next = await provider.auth.oauth.refresh(grant, new AbortController().signal);
  assert.equal(next.refresh, 'SYNTHETIC_NEW_REFRESH|synthetic-project');
  const auth = await provider.auth.oauth.toAuth(next);
  assert.equal(auth.headers['x-dsh-antigravity-project'], 'synthetic-project');
  assert(!JSON.stringify(auth).includes('SYNTHETIC_NEW_REFRESH'));
});

test('refresh failure discards upstream token/error text', async () => {
  const provider = antigravityProvider({ refresh: async () => { throw Error(key); } });
  await assert.rejects(provider.auth.oauth.refresh(grant, new AbortController().signal),
    error => error.message === `OAuth refresh failed for ${PROVIDER_ID}`);
});

test('generation preserves instructions, images, tools and reasoning without disabling DSH tool control', () => {
  const tools = [{ name: 'lookup', description: 'Lookup', parameters: { type: 'object', properties: { q: { type: 'string' } } } }];
  const ctx = context({ tools, messages: [{ role: 'user', timestamp: 0, content: [{ type: 'text', text: 'look' },
    { type: 'image', data: 'aGVsbG8=', mimeType: 'image/png' }] }] });
  const request = requestEnvelope(model, ctx, { reasoning: 'high', sessionId: 'fixture', maxTokens: 200 });
  assert.equal(request.request.systemInstruction.parts[0].text, 'System instruction');
  assert(request.request.contents[0].parts.some(p => p.inlineData));
  assert.equal(request.request.tools[0].functionDeclarations[0].name, 'lookup');
  assert.equal(request.request.generationConfig.maxOutputTokens, 200);
  assert(request.request.generationConfig.thinkingConfig);
  assert.equal(requestEnvelope(model, ctx, { toolChoice: 'none' }).request.tools, undefined);
});

test('stream unwraps fragmented UTF-8 SSE and reports usage', async () => {
  let sent;
  const response = streamResponse([{ candidates: [{ content: { parts: [{ thought: true, text: 'thinking' }] } }] }, stop,
    { usageMetadata: { promptTokenCount: 12, cachedContentTokenCount: 2, candidatesTokenCount: 3, thoughtsTokenCount: 4, totalTokenCount: 19 } }]);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const provider = antigravityProvider({ transport: async (url, init) => {
    sent = { url, init }; return new Response(new ReadableStream({ start(c) { for (const b of bytes) c.enqueue(Uint8Array.of(b)); c.close(); } }));
  } });
  const auth = await provider.auth.oauth.toAuth(grant);
  const events = [];
  const stream = provider.streamSimple(model, context(), { ...auth, sessionId: 'fixture' });
  for await (const e of stream) events.push(e.type);
  const result = await stream.result();
  assert(events.includes('thinking_delta')); assert(events.includes('text_delta'));
  assert.equal(result.stopReason, 'stop');
  assert.equal(result.content.find(p => p.type === 'text').text, '完成');
  assert.equal(result.usage.input, 10); assert.equal(result.usage.output, 7);
  assert.equal(sent.init.headers.Authorization, `Bearer ${key}`);
  assert(!sent.init.body.includes(key)); assert(!sent.init.body.includes('SYNTHETIC_REFRESH'));
  assert(!sent.init.headers['x-dsh-antigravity-project']);
  assert(sent.url.startsWith('https://daily-cloudcode-pa.googleapis.com/'));
});

test('a streamed tool call and signature survive the next round with its result', async () => {
  const provider = antigravityProvider({ transport: async () => streamResponse([{ candidates: [{ content: { parts: [
    { thought: true, thoughtSignature: 'c3ludGhldGljLXNpZ25hdHVyZQ==' }, { functionCall: { name: 'lookup', args: { q: 'hello' } } },
  ] }, finishReason: 'STOP' }] }]) });
  const auth = await provider.auth.oauth.toAuth(grant);
  const stream = provider.streamSimple(model, context(), auth);
  for await (const _ of stream) { /* consume */ }
  const result = await stream.result();
  assert.equal(result.stopReason, 'toolUse');
  const call = result.content[0];
  assert.equal(call.thoughtSignature, 'c3ludGhldGljLXNpZ25hdHVyZQ==');
  const next = requestEnvelope(model, context({ messages: [result,
    { role: 'toolResult', toolCallId: call.id, toolName: call.name, content: [{ type: 'text', text: 'found' }], isError: false, timestamp: 1 }] }), {});
  const part = next.request.contents.find(c => c.role === 'model').parts.find(p => p.functionCall);
  assert.equal(part.thoughtSignature, 'c3ludGhldGljLXNpZ25hdHVyZQ==');
  assert.equal(part.functionCall.id, call.id);
  const responsePart = next.request.contents.flatMap(c => c.parts).find(p => p.functionResponse);
  assert.equal(responsePart.functionResponse.id, call.id);
});

for (const [label, response] of [
  ['HTTP failure', () => new Response(key, { status: 403 })],
  ['truncated response', () => streamResponse([{ candidates: [{ content: { parts: [{ text: 'partial' }] } }] }])],
  ['embedded error', () => streamResponse([{ error: { message: key } }])],
  ['safety rejection', () => streamResponse([{ candidates: [{ finishReason: 'SAFETY' }] }])],
]) test(`${label} terminates with an error and never exposes upstream secrets`, async () => {
  const provider = antigravityProvider({ transport: async () => response() });
  const stream = provider.streamSimple(model, context(), await provider.auth.oauth.toAuth(grant));
  for await (const _ of stream) { /* consume */ }
  const result = await stream.result();
  assert.equal(result.stopReason, 'error'); assert(!result.errorMessage.includes(key));
});

test('cancelled generation aborts without a network request', async () => {
  const controller = new AbortController(); controller.abort();
  let sent = false;
  const provider = antigravityProvider({ transport: async () => { sent = true; return streamResponse([stop]); } });
  const stream = provider.streamSimple(model, context(), { ...await provider.auth.oauth.toAuth(grant), signal: controller.signal });
  for await (const _ of stream) { /* consume */ }
  assert.equal((await stream.result()).stopReason, 'aborted'); assert.equal(sent, false);
});

test('oversized SSE frames are bounded', async () => {
  await assert.rejects(async () => { for await (const _ of readFrames(new Response('data: ' + 'x'.repeat(1024 * 1024 + 1)).body)) {} }, /too large/);
});
