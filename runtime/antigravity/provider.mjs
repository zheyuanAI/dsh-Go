// SPDX-License-Identifier: MIT
// DSH model provider. OAuth/wire metadata comes from the pinned CortexKit core;
// DSH still owns conversations, tools, permissions and credential storage.
import { randomUUID } from 'node:crypto';
import {
  ANTIGRAVITY_ENDPOINT, ANTIGRAVITY_REDIRECT_URI, AgyRequestSessionStore,
  applyAgyNativeGenerationConfig, authorizeAntigravity, exchangeAntigravity,
  refreshAntigravityToken, parseRefreshParts, getPublicModelDefinitions,
  resolveAntigravityModel, buildAgyAgentRequestMetadata, orderAgyRequestPayloadInPlace,
  buildAntigravityHarnessUserAgent, fetchWithAgyCliTransport, isGeminiArgonModel,
} from '@cortexkit/antigravity-auth-core';
import { AssistantMessageEventStream } from '@earendil-works/pi-ai/utils/event-stream';
import { convertMessages, convertTools } from '@earendil-works/pi-ai/api/google-shared';
import { collapseSystemMessages, getCurrentTools, getInitialSystemMessage } from '@earendil-works/pi-ai/utils/transcript';
import { getSystemMessageText } from '@earendil-works/pi-ai/utils/text';

export const PROVIDER_ID = 'google-antigravity';
const PROJECT_HEADER = 'x-dsh-antigravity-project';
const noCost = () => ({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 });

export function antigravityModels() {
  return Object.entries(getPublicModelDefinitions())
    .filter(([, m]) => m.modalities.output.includes('text') && !m.modalities.output.includes('image'))
    .map(([id, m]) => ({
      id, name: m.name, provider: PROVIDER_ID, api: 'google-antigravity',
      baseUrl: ANTIGRAVITY_ENDPOINT, reasoning: m.reasoning,
      contextWindow: m.limit.context, maxTokens: m.limit.output,
      input: m.modalities.input.filter(x => x === 'text' || x === 'image'),
      cost: noCost(), thinkingLevelMap: { off: null, xhigh: null, max: null },
    }));
}

/** Validate a full redirect, including the attempt's state, before exchanging a code. */
export function callbackCode(answer, expectedState) {
  let url;
  try { url = new URL(answer.trim()); } catch { throw new Error('Missing authorization code or state mismatch'); }
  const callback = new URL(ANTIGRAVITY_REDIRECT_URI);
  if (url.origin !== callback.origin || url.pathname !== callback.pathname ||
      url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== expectedState ||
      url.searchParams.getAll('code').length !== 1 || !url.searchParams.get('code')) {
    throw new Error('Missing authorization code or state mismatch');
  }
  return url.searchParams.get('code');
}

/** Injectable operations keep tests offline and never require an account. */
export function antigravityProvider({
  authorize = authorizeAntigravity, exchange = exchangeAntigravity,
  refresh = refreshAntigravityToken, transport = fetchWithAgyCliTransport,
} = {}) {
  const sessions = new AgyRequestSessionStore('dsh-go');
  async function login(interaction) {
    interaction.signal.throwIfAborted();
    const auth = await authorize();
    interaction.signal.throwIfAborted();
    const state = new URL(auth.url).searchParams.get('state');
    if (!state) throw new Error('Antigravity authorization state is missing');
    interaction.notify({ type: 'auth_url', url: auth.url });
    const answer = await interaction.prompt({ type: 'manual_code', message: 'Paste the complete Antigravity callback URL', signal: interaction.signal });
    interaction.signal.throwIfAborted();
    const code = callbackCode(answer, state);
    const result = await exchange(code, state, { signal: interaction.signal });
    interaction.signal.throwIfAborted();
    if (result.type !== 'success' || !result.access || !result.refresh || !Number.isFinite(result.expires)) {
      throw new Error('Antigravity authorization failed');
    }
    return { type: 'oauth', access: result.access, refresh: result.refresh, expires: result.expires };
  }
  async function refreshGrant(credential, signal) {
    signal.throwIfAborted();
    try {
      const { refreshToken } = parseRefreshParts(credential.refresh);
      const result = await refresh(refreshToken);
      signal.throwIfAborted();
      if (!result.access || !result.refresh || !Number.isFinite(result.expires)) throw Error();
      const projects = credential.refresh.includes('|') ? credential.refresh.slice(credential.refresh.indexOf('|')) : '';
      return { ...credential, access: result.access, refresh: result.refresh + projects, expires: result.expires };
    } catch {
      signal.throwIfAborted();
      // Do not echo token service responses, request bodies or credential values.
      throw new Error(`OAuth refresh failed for ${PROVIDER_ID}`);
    }
  }
  async function toAuth(credential) {
    const project = parseRefreshParts(credential.refresh);
    const projectId = project.managedProjectId || project.projectId;
    if (!projectId || !credential.access) throw new Error(`OAuth auth derivation failed for ${PROVIDER_ID}`);
    return { apiKey: credential.access, headers: { [PROJECT_HEADER]: projectId } };
  }
  function stream(model, context, options = {}) {
    const events = new AssistantMessageEventStream();
    void runStream(events, model, context, options, transport, sessions);
    return events;
  }
  return {
    id: PROVIDER_ID, name: 'Antigravity', baseUrl: ANTIGRAVITY_ENDPOINT,
    getModels: antigravityModels,
    auth: { oauth: { name: 'Antigravity', isSubscription: true, login, refresh: refreshGrant, toAuth } },
    stream, streamSimple: stream,
  };
}

function resolvedModel(model, options) {
  const level = options.reasoning === 'xhigh' || options.reasoning === 'max' ? 'high' :
    options.reasoning === 'minimal' ? 'low' : options.reasoning;
  return resolveAntigravityModel(level && level !== 'off' ? `${model.id}-${level}` : model.id);
}

export function requestEnvelope(model, context, options, sessions = new AgyRequestSessionStore('dsh-go')) {
  const normalized = collapseSystemMessages(context);
  const resolved = resolvedModel(model, options);
  const wireModel = resolved.actualModel;
  const initial = getInitialSystemMessage(normalized.messages);
  const prompt = initial ? getSystemMessageText(initial) : '';
  const tools = options.toolChoice === 'none' ? undefined : convertTools(getCurrentTools(normalized.messages), true, false);
  // The picker uses an Antigravity-prefixed alias; Google's shared converter
  // detects tool IDs/image rules by the unprefixed model family. Rewrite only
  // same-model replay identities in this transient view, preserving signatures.
  const family = model.id.replace(/^antigravity-/, '');
  const replay = { messages: normalized.messages.map(message =>
    message.role === 'assistant' && message.model === model.id && message.provider === PROVIDER_ID
      ? { ...message, model: family } : message) };
  const request = {
    contents: convertMessages({ ...model, id: family }, replay),
    ...(prompt ? { systemInstruction: { parts: [{ text: prompt }] } } : {}),
    ...(tools ? { tools } : {}),
  };
  const generation = { maxOutputTokens: Math.min(options.maxTokens ?? model.maxTokens, model.maxTokens) };
  if (options.temperature !== undefined) generation.temperature = options.temperature;
  if (resolved.thinkingLevel !== undefined) generation.thinkingConfig = { includeThoughts: true, thinkingLevel: resolved.thinkingLevel };
  else if (resolved.thinkingBudget !== undefined) generation.thinkingConfig = { includeThoughts: true, thinkingBudget: resolved.thinkingBudget };
  applyAgyNativeGenerationConfig(wireModel, generation);
  request.generationConfig = generation;
  if (tools && !isGeminiArgonModel(wireModel)) request.toolConfig = { functionCallingConfig: { mode: options.toolChoice === 'none' ? 'NONE' : 'VALIDATED' } };
  const scope = sessions.beginRequest(options.sessionId ?? randomUUID());
  const metadata = buildAgyAgentRequestMetadata(scope.session, request, wireModel, scope.timestamp, { stepCountMode: 'cli' });
  request.labels = metadata.labels;
  request.sessionId = metadata.sessionId;
  orderAgyRequestPayloadInPlace(request);
  return { model: wireModel, requestId: metadata.requestId, request, userAgent: 'antigravity', requestType: 'agent' };
}

/** Bounded UTF-8 SSE frames; fragmented lines and multiline data are supported. */
export async function* readFrames(body) {
  if (!body) throw new Error('Antigravity stream has no body');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let buffer = '';
  let data = [];
  let frameBytes = 0;
  function line(value) {
    if (value.endsWith('\r')) value = value.slice(0, -1);
    if (value.startsWith('data:')) {
      const part = value.slice(5).replace(/^ /, '');
      frameBytes += Buffer.byteLength(part);
      if (frameBytes > 1024 * 1024) throw new Error('Antigravity stream frame is too large');
      data.push(part);
    }
    if (value !== '' || data.length === 0) return;
    const payload = data.join('\n');
    data = []; frameBytes = 0;
    if (payload !== '[DONE]') return JSON.parse(payload);
  }
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let end;
    while ((end = buffer.indexOf('\n')) !== -1) {
      const parsed = line(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (parsed !== undefined) yield parsed.response ?? parsed;
    }
    if (Buffer.byteLength(buffer) > 1024 * 1024) throw new Error('Antigravity stream line is too large');
  }
  buffer += decoder.decode();
  if (buffer) line(buffer);
  if (data.length) { const parsed = line(''); if (parsed !== undefined) yield parsed.response ?? parsed; }
}

async function runStream(events, model, context, options, transport, sessions) {
  const output = {
    role: 'assistant', content: [], api: model.api, provider: PROVIDER_ID, model: model.id,
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: noCost() },
    stopReason: 'pending', timestamp: Date.now(),
  };
  let response;
  try {
    options.signal?.throwIfAborted();
    const project = options.headers?.[PROJECT_HEADER];
    if (!options.apiKey || !project) throw new Error(`no credential for provider route "${PROVIDER_ID}"`);
    const envelope = { project, ...requestEnvelope(model, context, options, sessions) };
    await options.onPayload?.(envelope, model);
    response = await transport(`${ANTIGRAVITY_ENDPOINT}/v1internal:streamGenerateContent?alt=sse`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${options.apiKey}`, 'Content-Type': 'application/json',
        'User-Agent': buildAntigravityHarnessUserAgent(), 'Accept-Encoding': 'gzip' },
      body: JSON.stringify(envelope),
    }, { signal: options.signal });
    if (!response.ok) throw new Error(`Antigravity HTTP ${response.status}`);
    events.push({ type: 'start', partial: output });
    let finish;
    let pendingSignature;
    for await (const chunk of readFrames(response.body)) {
      options.signal?.throwIfAborted();
      if (chunk.error || chunk.promptFeedback?.blockReason) throw new Error('Antigravity rejected the request');
      const candidate = chunk.candidates?.[0];
      if (candidate?.finishReason) finish = candidate.finishReason;
      for (const part of candidate?.content?.parts ?? []) {
        const index = output.content.length;
        if (part.thought && !part.text && part.thoughtSignature) pendingSignature = part.thoughtSignature;
        if (typeof part.text === 'string' && (part.text.length || (!part.thought && part.thoughtSignature))) {
          const kind = part.thought ? 'thinking' : 'text';
          const block = { type: kind, [kind]: '' };
          if (part.thoughtSignature) block[part.thought ? 'thinkingSignature' : 'textSignature'] = part.thoughtSignature;
          output.content.push(block);
          events.push({ type: `${kind}_start`, contentIndex: index, partial: output });
          block[kind] = part.text;
          events.push({ type: `${kind}_delta`, contentIndex: index, delta: part.text, partial: output });
          events.push({ type: `${kind}_end`, contentIndex: index, content: part.text, partial: output });
        } else if (part.functionCall?.name) {
          const index = output.content.length;
          const signature = part.thoughtSignature ?? pendingSignature;
          pendingSignature = undefined;
          const toolCall = { type: 'toolCall', id: part.functionCall.id || randomUUID(), name: part.functionCall.name,
            arguments: {}, ...(signature ? { thoughtSignature: signature } : {}) };
          output.content.push(toolCall);
          events.push({ type: 'toolcall_start', contentIndex: index, partial: output });
          toolCall.arguments = part.functionCall.args ?? {};
          events.push({ type: 'toolcall_delta', contentIndex: index, delta: JSON.stringify(toolCall.arguments), partial: output });
          events.push({ type: 'toolcall_end', contentIndex: index, toolCall, partial: output });
        }
      }
      const usage = chunk.usageMetadata;
      if (usage) {
        output.usage.cacheRead = usage.cachedContentTokenCount ?? 0;
        output.usage.input = Math.max(0, (usage.promptTokenCount ?? 0) - output.usage.cacheRead);
        output.usage.output = (usage.candidatesTokenCount ?? 0) + (usage.thoughtsTokenCount ?? 0);
        output.usage.totalTokens = usage.totalTokenCount ?? output.usage.input + output.usage.cacheRead + output.usage.output;
      }
    }
    if (!finish) throw new Error('Antigravity stream ended without a finish reason');
    if (!['STOP', 'MAX_TOKENS'].includes(finish)) throw new Error('Antigravity blocked or rejected the response');
    output.stopReason = finish === 'MAX_TOKENS' ? 'length' : output.content.some(p => p.type === 'toolCall') ? 'toolUse' : 'stop';
    events.push({ type: 'done', reason: output.stopReason, message: output });
  } catch (error) {
    output.stopReason = options.signal?.aborted ? 'aborted' : 'error';
    // Upstream errors may contain tokens or model input. Only our fixed diagnostics escape.
    const safe = /^Antigravity (HTTP \d{3}|stream (?:ended without a finish reason|has no body|frame is too large|line is too large)|blocked or rejected the response|rejected the request)$/.test(error?.message ?? '');
    output.errorMessage = safe ? error.message : options.signal?.aborted ? 'Antigravity request cancelled' : 'Antigravity request failed';
    events.push({ type: 'error', reason: output.stopReason, error: output });
  } finally {
    try { await response?.body?.cancel(); } catch { /* already consumed */ }
    events.end();
  }
}
