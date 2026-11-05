// Public Sites deployment for the fork. Reuses the encrypted-link protocol.
import { fetchBlob, json, readCapped, remove, upload } from './api';
import type { Env } from './env';
import { clientKey } from './limits';
import { hmacHex } from './stats';
import { validateReport } from './usage';
import assets from 'dshgo:site-assets';

interface SitesEnv {
  BUCKET: R2Bucket;
  USAGE_SECRET?: string;
}

/** Atomic, bounded counters. Only keyed hashes are retained, never raw IPs. */
async function allow(env: SitesEnv, client: string, scope: string, seconds: number, limit: number): Promise<boolean> {
  const slot = Math.floor(Date.now() / (seconds * 1000));
  const hash = await hmacHex(env.USAGE_SECRET!, `${scope}:${slot}:${client}`, 16);
  const key = `quota/${scope}/${slot}/${hash}`;
  for (let attempt = 0; attempt < 4; attempt++) {
    const old = await env.BUCKET.get(key);
    const count = old ? Number(await old.text()) : 0;
    if (!Number.isFinite(count) || count >= limit) return false;
    const stored = await env.BUCKET.put(key, String(count + 1), {
      onlyIf: old ? { etagMatches: old.etag } : { etagDoesNotMatch: '*' },
      customMetadata: { expiresAt: String((slot + 1) * seconds * 1000) },
    });
    if (stored) return true;
  }
  return false;
}

async function sweep(env: SitesEnv): Promise<void> {
  const now = Date.now();
  for (const prefix of ['7d/', '30d/', 'usage/', 'quota/']) {
    // A bounded sweep on requests also removes unread expired shares.
    const list = await env.BUCKET.list({ prefix, limit: 100, include: ['customMetadata'] });
    const expired = list.objects.filter(object => {
      if (prefix === '7d/' || prefix === '30d/') {
        return object.uploaded.getTime() + (prefix === '7d/' ? 7 : 30) * 86400000 <= now;
      }
      return Number(object.customMetadata?.expiresAt ?? Infinity) <= now;
    });
    if (expired.length) await env.BUCKET.delete(expired.map(object => object.key));
  }
}

async function collectUsage(request: Request, env: SitesEnv): Promise<Response> {
  if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' });
  if (!(await allow(env, clientKey(request), 'usage', 60, 20))) return json(429, { error: 'rate_limited' });
  if (!/^application\/json\s*(;|$)/i.test(request.headers.get('Content-Type') ?? '')) {
    return json(415, { error: 'unsupported_media_type' });
  }
  const bytes = await readCapped(request, 2048);
  if (!bytes) return json(413, { error: 'too_large' });
  let report;
  try {
    report = validateReport(JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)));
  } catch {
    return json(400, { error: 'bad_report' });
  }
  const { iid, ...fields } = report;
  const device = await hmacHex(env.USAGE_SECRET!, `iid\n${iid}`, 16);
  // Latest cumulative daily report replaces repeats. No public read endpoint.
  await env.BUCKET.put(`usage/${report.day}/${device}.json`, JSON.stringify({ ...fields, device }), {
    customMetadata: { expiresAt: String(Date.parse(`${report.day}T00:00:00Z`) + 31 * 86400000) },
  });
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

async function route(request: Request, env: SitesEnv, ctx: ExecutionContext): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (!env.BUCKET || !env.USAGE_SECRET) return json(503, { error: 'service_unavailable' });
  if (path === '/api/health' && request.method === 'GET') {
    await env.BUCKET.head('health');
    return json(200, { service: 'dsh-go-services', v: 1, sharing: true, usage: true });
  }
  if (path.startsWith('/api/')) {
    ctx.waitUntil(sweep(env).catch(() => {}));
    if (path === '/api/usage/v1') return collectUsage(request, env);
    const apiEnv = { ...env, MAX_BYTES: String(20 * 1024 * 1024) } as Env;
    if (path === '/api/v1/c' && request.method === 'POST') {
      const client = clientKey(request);
      if (!(await allow(env, client, 'upload-minute', 60, 5)) || !(await allow(env, client, 'upload-hour', 3600, 20))) {
        return json(429, { error: 'rate_limited' }, { 'Retry-After': '60' });
      }
      return upload(request, apiEnv);
    }
    const match = /^\/api\/v1\/c\/([0-9A-Za-z]{10})$/.exec(path);
    if (match) {
      if (!(await allow(env, clientKey(request), 'read', 60, 120))) return json(429, { error: 'rate_limited' });
      if (request.method === 'GET') return fetchBlob(request, apiEnv, match[1]!);
      if (request.method === 'DELETE') return remove(request, apiEnv, match[1]!);
      return json(405, { error: 'method_not_allowed' });
    }
    return json(404, { error: 'not_found' });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return json(405, { error: 'method_not_allowed' });
  const assetPath = /^\/c\/[0-9A-Za-z]{10}\/?$/.test(path) ? '/c.html' : path === '/share' ? '/share/' : path;
  const asset = assets[assetPath];
  if (!asset) return json(404, { error: 'not_found' });
  return new Response(request.method === 'HEAD' ? null : asset.body, {
    headers: {
      'Content-Type': asset.type, 'Cache-Control': 'no-cache',
      'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex',
    },
  });
}

export default {
  async fetch(request: Request, env: SitesEnv, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch {
      // Never log request URLs, fragments, bodies or credentials.
      return json(503, { error: 'service_unavailable' });
    }
  },
};
