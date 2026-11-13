// services/share-worker/src/ids.ts
var ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
var ID_LENGTH = 10;
var TIERS = [
  { ttl: "7d", prefix: "7d/", days: 7, from: 0, to: 20 },
  // 0-9 A-J
  { ttl: "30d", prefix: "30d/", days: 30, from: 20, to: 40 },
  // K-Z a-d
  { ttl: "forever", prefix: "keep/", days: null, from: 40, to: 62 }
  // e-z
];
var DEFAULT_TTL = "30d";
var ID_PATTERN = new RegExp(`^[0-9A-Za-z]{${ID_LENGTH}}$`);
function parseTtl(value) {
  if (value === null || value === "") return DEFAULT_TTL;
  return TIERS.some((t) => t.ttl === value) ? value : null;
}
function tierOfTtl(ttl) {
  return TIERS.find((t) => t.ttl === ttl);
}
function tierOfId(id) {
  if (!ID_PATTERN.test(id)) return null;
  const at = ALPHABET.indexOf(id[0]);
  return TIERS.find((t) => at >= t.from && at < t.to) ?? null;
}
function objectKey(id) {
  const tier = tierOfId(id);
  return tier ? tier.prefix + id : null;
}
function randomBelow(n) {
  const limit = 256 - 256 % n;
  const buf = new Uint8Array(16);
  for (; ; ) {
    crypto.getRandomValues(buf);
    for (const b of buf) if (b < limit) return b % n;
  }
}
function newId(ttl) {
  const tier = tierOfTtl(ttl);
  let id = ALPHABET[tier.from + randomBelow(tier.to - tier.from)];
  while (id.length < ID_LENGTH) id += ALPHABET[randomBelow(ALPHABET.length)];
  return id;
}
function expiresAt(tier, uploaded) {
  return tier.days === null ? null : new Date(uploaded.getTime() + tier.days * 864e5);
}

// services/share-worker/src/limits.ts
function clientKey(request) {
  const ip = request.headers.get("CF-Connecting-IP")?.trim() || "unknown";
  if (!ip.includes(":")) return ip;
  return expandV6(ip).slice(0, 4).join(":") + "::/64";
}
function expandV6(ip) {
  const clean = ip.split("%")[0].toLowerCase();
  const [head, tail] = clean.includes("::") ? clean.split("::", 2) : [clean, null];
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const fill = tail === null ? [] : new Array(Math.max(0, 8 - left.length - right.length)).fill("0");
  return [...left, ...fill, ...right].map((g) => g.replace(/^0+(?=.)/, "") || "0");
}
async function burstAllowed(limiter, key) {
  if (!limiter) return true;
  try {
    return (await limiter.limit({ key })).success;
  } catch (e) {
    console.error("rate limit binding failed", e instanceof Error ? e.message : String(e));
    return true;
  }
}
async function hashKey(key) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("dshgo-share:" + key));
  return [...new Uint8Array(digest).slice(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function uploadQuota(env, key, now = Date.now()) {
  const perHour = Number(env.UPLOADS_PER_HOUR ?? "20") || 20;
  const hour = Math.floor(now / 36e5);
  const retryAfter = Math.max(1, Math.ceil(((hour + 1) * 36e5 - now) / 1e3));
  const kv = env.QUOTA;
  if (!kv) return { allowed: true, retryAfter, commit: async () => {
  } };
  const kvKey = `up:${hour}:${await hashKey(key)}`;
  let count = 0;
  try {
    count = Number(await kv.get(kvKey)) || 0;
  } catch {
    count = 0;
  }
  return {
    allowed: count < perHour,
    retryAfter,
    commit: async () => {
      try {
        await kv.put(kvKey, String(count + 1), { expirationTtl: 2 * 3600 });
      } catch {
      }
    }
  };
}

// services/share-worker/src/api.ts
var MAGIC = [68, 83, 71, 49];
var MIN_BYTES = 4 + 12 + 16;
var DEFAULT_MAX_BYTES = 20 * 1024 * 1024;
var API_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex"
};
function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...API_HEADERS, "Content-Type": "application/json; charset=utf-8", ...extra }
  });
}
var error = (status, code, extra) => json(status, { error: code }, extra);
function maxBytes(env) {
  const n = Number(env.MAX_BYTES);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_BYTES;
}
async function readCapped(request, limit) {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {
      });
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([sha256Hex(a), sha256Hex(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
async function upload(request, env) {
  const url = new URL(request.url);
  const ttl = parseTtl(url.searchParams.get("ttl"));
  if (!ttl) return error(400, "bad_ttl");
  const type = (request.headers.get("Content-Type") ?? "").split(";")[0].trim().toLowerCase();
  if (type !== "application/octet-stream") return error(415, "bad_content_type");
  const limit = maxBytes(env);
  const declared = request.headers.get("Content-Length");
  if (declared !== null && Number(declared) > limit) return error(413, "too_large");
  const client = clientKey(request);
  if (!await burstAllowed(env.UPLOAD_BURST, client)) return error(429, "rate_limited", { "Retry-After": "60" });
  const quota = await uploadQuota(env, client);
  if (!quota.allowed) return error(429, "rate_limited", { "Retry-After": String(quota.retryAfter) });
  const body = await readCapped(request, limit);
  if (body === null) return error(413, "too_large");
  if (body.byteLength < MIN_BYTES || MAGIC.some((b, i) => body[i] !== b)) return error(400, "bad_format");
  const tier = tierOfTtl(ttl);
  const deleteToken = randomToken();
  const tokenHash = await sha256Hex(deleteToken);
  for (let attempt = 0; attempt < 4; attempt++) {
    const id = newId(ttl);
    const key = tier.prefix + id;
    if (await env.BUCKET.head(key)) continue;
    const stored = await env.BUCKET.put(key, body, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { dt: tokenHash }
    });
    await quota.commit();
    const expires = expiresAt(tier, stored?.uploaded ?? /* @__PURE__ */ new Date());
    return json(201, { id, deleteToken, expiresAt: expires ? expires.toISOString() : null });
  }
  return error(503, "try_again");
}
async function fetchBlob(request, env, id) {
  if (!await burstAllowed(env.READ_LIMIT, clientKey(request))) {
    return error(429, "rate_limited", { "Retry-After": "60" });
  }
  const key = objectKey(id);
  if (!key) return error(404, "not_found");
  const object = await env.BUCKET.get(key);
  if (!object) return error(404, "not_found");
  const expires = expiresAt(tierOfId(id), object.uploaded);
  if (expires && expires.getTime() <= Date.now()) {
    await object.body.cancel().catch(() => {
    });
    return error(404, "not_found");
  }
  return new Response(object.body, {
    status: 200,
    headers: {
      ...API_HEADERS,
      "Content-Type": "application/octet-stream",
      "Content-Length": String(object.size),
      "Content-Disposition": `attachment; filename="${id}.dsg"`
    }
  });
}
async function remove(request, env, id) {
  const admin = request.headers.get("X-Admin-Key");
  const auth = request.headers.get("Authorization") ?? "";
  const bearer = /^Bearer\s+([A-Za-z0-9_-]{16,128})$/.exec(auth.trim())?.[1] ?? null;
  if (admin === null && bearer === null) return error(401, "unauthorized");
  if (admin === null && !await burstAllowed(env.READ_LIMIT, clientKey(request))) {
    return error(429, "rate_limited", { "Retry-After": "60" });
  }
  const key = objectKey(id);
  if (!key) return error(404, "not_found");
  const object = await env.BUCKET.head(key);
  if (!object) return error(404, "not_found");
  let allowed = false;
  if (admin !== null) {
    allowed = !!env.ADMIN_KEY && env.ADMIN_KEY.length >= 32 && await sameSecret(admin, env.ADMIN_KEY);
  } else if (bearer !== null) {
    const stored = object.customMetadata?.dt ?? "";
    allowed = stored.length === 64 && await sameSecret(await sha256Hex(bearer), stored);
  }
  if (!allowed) return error(403, "forbidden");
  await env.BUCKET.delete(key);
  return new Response(null, { status: 204, headers: API_HEADERS });
}

// services/share-worker/src/stats.ts
var DAY_MS = 864e5;
var OFFSET_MS = 8 * 36e5;
function statsDay(now = Date.now()) {
  return new Date(now + OFFSET_MS).toISOString().slice(0, 10);
}
function addDays(day, days) {
  return new Date(Date.parse(`${day}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}
var encoder = new TextEncoder();
function hex(bytes, take) {
  return [...new Uint8Array(bytes).slice(0, take)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmacHex(key, message, bytes) {
  const k = typeof key === "string" ? await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]) : key;
  return hex(await crypto.subtle.sign("HMAC", k, encoder.encode(message)), bytes);
}

// services/share-worker/src/usage.ts
var COUNT_LIMITS = { turns: 5e3, voice: 2e3, phone: 2e3, share: 1e3, gen: 1e3, plugins: 500 };
var COUNT_KEYS = Object.keys(COUNT_LIMITS);
var FIELDS = ["v", "iid", "day", "app", "build", "sdk", "abi", "maker", "lang", "engine", "counts"];
var ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];
var ENGINES = ["direct", "proot", "none"];
var Invalid = class extends Error {
  constructor(code, field) {
    super(`${code}: ${field}`);
    this.code = code;
    this.field = field;
  }
  code;
  field;
};
var isObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function only(obj, keys, prefix) {
  for (const k of Object.keys(obj)) if (!keys.includes(k)) throw new Invalid("unknown_field", prefix + k);
  for (const k of keys) if (!(k in obj)) throw new Invalid("missing_field", prefix + k);
}
function int(v, field, min, max) {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw new Invalid("invalid", field);
  return v;
}
function str(v, field, pattern) {
  if (typeof v !== "string" || !pattern.test(v)) throw new Invalid("invalid", field);
  return v;
}
function validateReport(body, now = Date.now()) {
  if (!isObject(body)) throw new Invalid("invalid", "body");
  only(body, FIELDS, "");
  if (body.v !== 1) throw new Invalid("invalid", "v");
  const iid = str(body.iid, "iid", /^[A-Za-z0-9_-]{21}[AQgw](?:==)?$/).slice(0, 22);
  const day = str(body.day, "day", /^\d{4}-\d{2}-\d{2}$/);
  const today = statsDay(now);
  const at = Date.parse(`${day}T00:00:00Z`);
  if (!Number.isFinite(at) || new Date(at).toISOString().slice(0, 10) !== day) throw new Invalid("invalid", "day");
  if (day < addDays(today, -7) || day > addDays(today, 1)) throw new Invalid("invalid", "day");
  const app = str(body.app, "app", /^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-[0-9A-Za-z.]{1,20})?$/);
  const build = int(body.build, "build", 1, 21e8);
  const sdk = int(body.sdk, "sdk", 26, 60);
  const abi = str(body.abi, "abi", /^[a-z0-9_-]{1,16}$/);
  if (!ABIS.includes(abi)) throw new Invalid("invalid", "abi");
  const maker = str(body.maker, "maker", /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$/).trim().toLowerCase();
  const lang = str(body.lang, "lang", /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/);
  const engine = str(body.engine, "engine", /^[a-z]{1,8}$/);
  if (!ENGINES.includes(engine)) throw new Invalid("invalid", "engine");
  if (!isObject(body.counts)) throw new Invalid("invalid", "counts");
  only(body.counts, COUNT_KEYS, "counts.");
  const counts = {};
  for (const k of COUNT_KEYS) counts[k] = int(body.counts[k], `counts.${k}`, 0, COUNT_LIMITS[k]);
  return { iid, day, app, build, sdk, abi, maker, lang, engine, counts };
}

// viewer:assets
var assets_default = { "/c.html": { "body": `<!doctype html>\r
<html lang="zh-CN">\r
<head>\r
<meta charset="utf-8">\r
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\r
<meta name="referrer" content="no-referrer">\r
<meta name="robots" content="noindex">\r
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-cmldXES/6uNWse5e9HfHWdHdr/1zV+Yt+IxSvrv7D1g='; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'">\r
<meta name="color-scheme" content="light dark">\r
<title>dsh-go \u5BF9\u8BDD</title>\r
<style>/* dsh-go conversation viewer (viewer.js). Shared by the landing page and the\r
   self-contained page the app exports (app/tool/make_replay_viewer.py inlines\r
   it). Colours follow the app's default theme (\u96FE\u84DD), light and dark. */\r
\r
.dv {\r
  --dv-bg-top: #ebf1fe;\r
  --dv-bg-bottom: #f6f7fc;\r
  --dv-ink: #1e232e;\r
  --dv-ink-2: #4f5562;\r
  --dv-ink-3: #646974;\r
  --dv-ink-4: #a1a5ac;\r
  --dv-line: rgba(11, 21, 45, 0.08);\r
  --dv-glass: rgba(255, 255, 255, 0.78);\r
  --dv-card: rgba(255, 255, 255, 0.62);\r
  --dv-solid: #fbfcff;\r
  --dv-bubble: #d9e4fd;\r
  --dv-primary: #4b67b4;\r
  --dv-on-primary: #ffffff;\r
  --dv-tint: rgba(30, 35, 46, 0.06);\r
  --dv-code-bg: #edf0f6;\r
  --dv-code-head: #e7ebf3;\r
  --dv-code-line: #dbdee5;\r
  --dv-danger: #a54743;\r
  --dv-success: #337250;\r
  --dv-warning: #936123;\r
  --dv-shadow: 0 8px 24px rgba(11, 21, 45, 0.08), 0 1px 3px rgba(11, 21, 45, 0.05);\r
  --dv-hl-k: #8e3e9e; --dv-hl-s: #2f7a4b; --dv-hl-c: #8a8f9a; --dv-hl-n: #9a5b13; --dv-hl-t: #2f5fb3; --dv-hl-f: #315aa8;\r
  /* Tool tones: terminal, read, edit, search, web, agent, plan, neutral. */\r
  --dv-t0: #e6eaf2; --dv-o0: #343d51;\r
  --dv-t1: #daecff; --dv-o1: #173f65;\r
  --dv-t2: #fae6cd; --dv-o2: #543600;\r
  --dv-t3: #ede5fe; --dv-o3: #443261;\r
  --dv-t4: #d7f1e2; --dv-o4: #034a2e;\r
  --dv-t5: #f9e2f0; --dv-o5: #582b4a;\r
  --dv-t6: #d0f1f0; --dv-o6: #004747;\r
  --dv-t7: #e7e9ef; --dv-o7: #363d4c;\r
  color: var(--dv-ink);\r
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", "Segoe UI", sans-serif;\r
  -webkit-text-size-adjust: 100%;\r
}\r
@media (prefers-color-scheme: dark) {\r
  .dv {\r
    --dv-bg-top: #1d222c;\r
    --dv-bg-bottom: #1b1c23;\r
    --dv-ink: #e6e9f0;\r
    --dv-ink-2: #b6bbc5;\r
    --dv-ink-3: #9a9ea9;\r
    --dv-ink-4: #656971;\r
    --dv-line: rgba(255, 255, 255, 0.09);\r
    --dv-glass: rgba(43, 48, 60, 0.82);\r
    --dv-card: rgba(255, 255, 255, 0.05);\r
    --dv-solid: #232730;\r
    --dv-bubble: #293144;\r
    --dv-primary: #97b1f0;\r
    --dv-on-primary: #121c34;\r
    --dv-tint: rgba(255, 255, 255, 0.08);\r
    --dv-code-bg: #14171e;\r
    --dv-code-head: #1a1e26;\r
    --dv-code-line: #2f333a;\r
    --dv-danger: #e69089;\r
    --dv-success: #8bcca6;\r
    --dv-warning: #e6bd7c;\r
    --dv-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 1px 3px rgba(0, 0, 0, 0.25);\r
    --dv-hl-k: #deb2e9; --dv-hl-s: #9ad5a5; --dv-hl-c: #7c8089; --dv-hl-n: #e3be80; --dv-hl-t: #a0c6ff; --dv-hl-f: #87ade4;\r
    --dv-t0: #303540; --dv-o0: #d1d8e5;\r
    --dv-t1: #21374e; --dv-o1: #c0dbf8;\r
    --dv-t2: #443116; --dv-o2: #ebd3b4;\r
    --dv-t3: #39304b; --dv-o3: #dcd1f3;\r
    --dv-t4: #1d3d2d; --dv-o4: #bde2cd;\r
    --dv-t5: #452c3d; --dv-o5: #edcce1;\r
    --dv-t6: #0f3d3d; --dv-o6: #b3e2e1;\r
    --dv-t7: #32353d; --dv-o7: #d3d7e1;\r
  }\r
}\r
\r
.dv-page { margin: 0; min-height: 100vh; background: linear-gradient(180deg, var(--dv-bg-top), var(--dv-bg-bottom)) fixed; }\r
.dv *, .dv *::before, .dv *::after { box-sizing: border-box; }\r
.dv { min-height: 100vh; display: flex; flex-direction: column; background: linear-gradient(180deg, var(--dv-bg-top), var(--dv-bg-bottom)); }\r
/* Reset at zero specificity, so the component classes below win. */\r
.dv :where(button) { font: inherit; color: inherit; border: 0; background: none; padding: 0; cursor: pointer; -webkit-tap-highlight-color: transparent; }\r
.dv button:focus-visible, .dv a:focus-visible, .dv input:focus-visible { outline: 2px solid var(--dv-primary); outline-offset: 2px; }\r
.dv [hidden] { display: none !important; }\r
\r
/* \u2500\u2500 Top bar: title, then the transport capsule \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-bar {\r
  position: sticky; top: 0; z-index: 5;\r
  padding: max(12px, env(safe-area-inset-top)) 12px 10px;\r
  background: linear-gradient(180deg, var(--dv-bg-top) 70%, transparent);\r
}\r
.dv-bar-inner { max-width: 744px; margin: 0 auto; display: grid; gap: 10px; }\r
.dv-head { display: flex; align-items: center; gap: 12px; padding: 0 4px; min-width: 0; }\r
.dv-head-text { min-width: 0; flex: 1; }\r
.dv-title { margin: 0; font-size: 17px; line-height: 1.35; font-weight: 600; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow-wrap: anywhere; }\r
.dv-sub { font-size: 12px; line-height: 1.4; color: var(--dv-ink-3); margin-top: 2px; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\r
.dv-pill {\r
  flex: none; height: 36px; padding: 0 14px; border-radius: 999px; font-size: 14px; font-weight: 500;\r
  background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line);\r
  -webkit-backdrop-filter: blur(18px) saturate(1.3); backdrop-filter: blur(18px) saturate(1.3);\r
}\r
.dv-transport {\r
  display: flex; align-items: center; gap: 8px; height: 44px; padding: 4px; border-radius: 999px;\r
  background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line);\r
  -webkit-backdrop-filter: blur(18px) saturate(1.3); backdrop-filter: blur(18px) saturate(1.3);\r
}\r
.dv-key { flex: none; width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; background: var(--dv-tint); transition: transform 0.12s ease; }\r
.dv-key:active { transform: scale(0.94); }\r
.dv-key svg { width: 20px; height: 20px; fill: currentColor; }\r
.dv-speed { flex: none; min-width: 44px; height: 36px; padding: 0 10px; border-radius: 999px; background: var(--dv-tint); font-size: 14px; font-weight: 600; font-variant-numeric: tabular-nums; }\r
.dv-time { flex: none; font-size: 12px; color: var(--dv-ink-3); font-variant-numeric: tabular-nums; min-width: 72px; text-align: center; }\r
.dv-seek { flex: 1; min-width: 40px; height: 36px; margin: 0; background: transparent; -webkit-appearance: none; appearance: none; cursor: pointer; --dv-p: 0%; }\r
.dv-seek::-webkit-slider-runnable-track { height: 4px; border-radius: 2px; background: linear-gradient(90deg, var(--dv-primary) var(--dv-p), var(--dv-tint) var(--dv-p)); }\r
.dv-seek::-moz-range-track { height: 4px; border-radius: 2px; background: var(--dv-tint); }\r
.dv-seek::-moz-range-progress { height: 4px; border-radius: 2px; background: var(--dv-primary); }\r
.dv-seek::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; margin-top: -6px; border-radius: 50%; background: var(--dv-primary); border: 2px solid var(--dv-solid); box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2); }\r
.dv-seek::-moz-range-thumb { width: 14px; height: 14px; border-radius: 50%; background: var(--dv-primary); border: 2px solid var(--dv-solid); }\r
\r
/* \u2500\u2500 The conversation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-list { flex: 1; width: 100%; max-width: 752px; margin: 0 auto; padding: 8px 16px 24px; }\r
.dv-row { margin-top: 8px; animation: dv-in 0.24s ease-out both; }\r
.dv-row.dv-quiet { animation: none; }\r
.dv-row.dv-user { margin-top: 24px; display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }\r
.dv-row.dv-user:first-child { margin-top: 4px; }\r
.dv-row.dv-proc + .dv-row.dv-proc { margin-top: 0; }\r
@keyframes dv-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }\r
@media (prefers-reduced-motion: reduce) { .dv-row { animation: none; } .dv-caret { animation: none !important; } }\r
\r
.dv-bubble { max-width: min(85%, 560px); padding: 10px 14px; border-radius: 20px; background: var(--dv-bubble); white-space: pre-wrap; overflow-wrap: anywhere; }\r
.dv-shots { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; max-width: 85%; }\r
.dv-shot { display: block; border-radius: 14px; overflow: hidden; background: var(--dv-tint); border: 0.5px solid var(--dv-line); }\r
.dv-shot img { display: block; width: 100%; height: 100%; object-fit: cover; }\r
.dv-shot.dv-one { max-width: 208px; max-height: 208px; }\r
.dv-shot.dv-one img { object-fit: contain; height: auto; max-height: 208px; }\r
.dv-shot.dv-many { width: 88px; height: 88px; }\r
.dv-shot.dv-missing { width: 88px; height: 88px; display: grid; place-items: center; color: var(--dv-ink-4); font-size: 12px; }\r
.dv-file { display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 14px; background: var(--dv-card); border: 0.5px solid var(--dv-line); font-size: 13px; }\r
.dv-file span:last-child { color: var(--dv-ink-3); }\r
.dv-source { font-size: 12px; color: var(--dv-ink-3); }\r
\r
/* Replies: full-width Markdown, no frame. */\r
.dv-md { overflow-wrap: anywhere; }\r
.dv-md > :first-child { margin-top: 0; }\r
.dv-md > :last-child { margin-bottom: 0; }\r
.dv-md p { margin: 0 0 12px; }\r
.dv-md h1, .dv-md h2, .dv-md h3, .dv-md h4, .dv-md h5, .dv-md h6 { margin: 20px 0 8px; line-height: 1.35; font-weight: 600; }\r
.dv-md h1 { font-size: 22px; } .dv-md h2 { font-size: 19px; } .dv-md h3 { font-size: 17px; } .dv-md h4, .dv-md h5, .dv-md h6 { font-size: 16px; }\r
.dv-md ul, .dv-md ol { margin: 0 0 12px; padding-left: 24px; }\r
.dv-md li { margin: 2px 0; }\r
.dv-md li > ul, .dv-md li > ol { margin: 2px 0 0; }\r
.dv-md blockquote { margin: 0 0 12px; padding: 0 0 0 12px; border-left: 3px solid var(--dv-line); color: var(--dv-ink-2); }\r
.dv-md hr { border: 0; border-top: 1px solid var(--dv-line); margin: 16px 0; }\r
.dv-md a { color: var(--dv-primary); text-decoration: none; }\r
.dv-md a:hover { text-decoration: underline; }\r
.dv-md code { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; padding: 1px 5px; border-radius: 6px; background: var(--dv-code-bg); }\r
.dv-md table { border-collapse: collapse; margin: 0 0 12px; display: block; overflow-x: auto; max-width: 100%; font-size: 14px; }\r
.dv-md th, .dv-md td { border: 1px solid var(--dv-line); padding: 6px 10px; text-align: left; vertical-align: top; }\r
.dv-md th { font-weight: 600; background: var(--dv-tint); }\r
.dv-md .dv-math { font-family: "JetBrains Mono", ui-monospace, Menlo, monospace; font-size: 14px; color: var(--dv-ink-2); }\r
.dv-code { margin: 0 0 12px; border-radius: 14px; overflow: hidden; background: var(--dv-code-bg); border: 0.5px solid var(--dv-code-line); }\r
.dv-code-head { display: flex; align-items: center; justify-content: space-between; height: 36px; padding: 0 8px 0 14px; background: var(--dv-code-head); font-size: 12px; color: var(--dv-ink-3); }\r
.dv-code-head button { height: 28px; padding: 0 8px; border-radius: 8px; font-size: 12px; color: var(--dv-ink-3); }\r
.dv-code pre { margin: 0; padding: 12px 14px; overflow-x: auto; font: 13px/1.55 "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }\r
.dv-code pre code { padding: 0; background: none; font-size: inherit; border-radius: 0; }\r
.dv-k { color: var(--dv-hl-k); } .dv-s { color: var(--dv-hl-s); } .dv-c { color: var(--dv-hl-c); font-style: italic; }\r
.dv-n { color: var(--dv-hl-n); } .dv-t { color: var(--dv-hl-t); } .dv-f { color: var(--dv-hl-f); }\r
.dv-add { color: var(--dv-success); } .dv-del { color: var(--dv-danger); }\r
.dv-caret { display: inline-block; width: 8px; height: 1.05em; margin-left: 2px; vertical-align: -0.15em; border-radius: 2px; background: var(--dv-primary); animation: dv-blink 1s steps(2, start) infinite; }\r
@keyframes dv-blink { to { visibility: hidden; } }\r
.dv-cut { margin-top: 8px; font-size: 13px; color: var(--dv-danger); }\r
.dv-foot-note { margin-top: 4px; font-size: 12px; color: var(--dv-ink-3); font-variant-numeric: tabular-nums; }\r
\r
/* Process lines: thinking, tools, the folded turn. */\r
.dv-line { display: flex; align-items: center; gap: 8px; min-height: 32px; padding: 4px 0; font-size: 14px; color: var(--dv-ink-2); cursor: pointer; user-select: none; }\r
.dv-line .dv-label { flex: none; }\r
.dv-line .dv-detail { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dv-ink-3); }\r
.dv-line .dv-detail.dv-mono { font: 13px "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace; }\r
.dv-line .dv-state { flex: none; font-size: 12px; color: var(--dv-ink-3); }\r
.dv-line .dv-state.dv-bad { color: var(--dv-danger); }\r
.dv-chev { flex: none; width: 16px; height: 16px; fill: var(--dv-ink-3); transition: transform 0.2s ease; }\r
.dv-open > .dv-line .dv-chev { transform: rotate(180deg); }\r
.dv-glyph { flex: none; width: 22px; height: 22px; border-radius: 7px; display: grid; place-items: center; }\r
.dv-glyph svg { width: 13px; height: 13px; fill: currentColor; }\r
.dv-spin { flex: none; width: 14px; height: 14px; border-radius: 50%; border: 2px solid var(--dv-tint); border-top-color: var(--dv-primary); animation: dv-rot 0.8s linear infinite; }\r
@keyframes dv-rot { to { transform: rotate(360deg); } }\r
.dv-body { margin: 0 0 4px 10px; padding: 4px 0 4px 18px; border-left: 1.5px solid var(--dv-line); }\r
.dv-think { font-size: 14px; color: var(--dv-ink-3); white-space: pre-wrap; overflow-wrap: anywhere; }\r
.dv-out { margin: 4px 0; padding: 10px 12px; border-radius: 12px; background: var(--dv-code-bg); font: 12px/1.5 "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 320px; overflow: auto; color: var(--dv-ink-2); }\r
.dv-out-label { font-size: 12px; color: var(--dv-ink-3); margin-top: 6px; }\r
.dv-notice { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dv-ink-3); padding: 4px 0; }\r
.dv-notice.dv-bad { color: var(--dv-danger); }\r
.dv-cmd { font: 13px "JetBrains Mono", ui-monospace, Menlo, monospace; color: var(--dv-ink-2); padding: 4px 0; }\r
.dv-cmd span { color: var(--dv-ink-3); font-family: inherit; }\r
.dv-fold-ok { flex: none; width: 16px; height: 16px; fill: var(--dv-success); }\r
\r
/* \u2500\u2500 Dock: todo list and goal, above the bottom actions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-bottom { position: sticky; bottom: 0; z-index: 4; padding: 12px 12px max(12px, env(safe-area-inset-bottom)); background: linear-gradient(0deg, var(--dv-bg-bottom) 70%, transparent); }\r
.dv-bottom-inner { max-width: 744px; margin: 0 auto; display: grid; gap: 8px; }\r
.dv-dock { border-radius: 20px; background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line); -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px); overflow: hidden; }\r
.dv-dock-row { display: flex; align-items: center; gap: 8px; min-height: 40px; padding: 6px 14px; font-size: 13px; cursor: pointer; }\r
.dv-dock-row + .dv-dock-row { border-top: 0.5px solid var(--dv-line); }\r
.dv-dock-row b { font-weight: 600; font-variant-numeric: tabular-nums; }\r
.dv-dock-row .dv-detail { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dv-ink-2); }\r
.dv-todos { list-style: none; margin: 0; padding: 0 14px 10px 36px; font-size: 13px; max-height: 30vh; overflow: auto; }\r
.dv-todos li { padding: 3px 0; }\r
.dv-todos li.dv-done { color: var(--dv-ink-3); text-decoration: line-through; }\r
.dv-todos li.dv-now { font-weight: 600; }\r
.dv-actions { display: flex; gap: 12px; }\r
.dv-btn { flex: 1; display: flex; align-items: center; justify-content: center; height: 48px; border-radius: 999px; font-size: 16px; font-weight: 600; text-decoration: none; }\r
.dv-btn.dv-primary { background: var(--dv-primary); color: var(--dv-on-primary); }\r
.dv-btn.dv-secondary { color: var(--dv-ink); background: var(--dv-glass); border: 0.5px solid var(--dv-line); box-shadow: var(--dv-shadow); }\r
\r
/* Picture viewer. */\r
.dv-lightbox { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; background: rgba(0, 0, 0, 0.86); padding: 16px; cursor: zoom-out; }\r
.dv-lightbox img { max-width: 100%; max-height: 100%; border-radius: 8px; }\r
\r
/* Opener (landing page without a link): pick or drop a file. */\r
.dv-open-card { width: calc(100% - 32px); max-width: 440px; margin: 15vh auto 0; padding: 32px 20px 24px; border-radius: 28px; background: var(--dv-solid); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line); text-align: center; }\r
.dv-open-card h1 { font-size: 21px; margin: 0 0 6px; font-weight: 600; }\r
.dv-open-card p { margin: 0 0 20px; color: var(--dv-ink-3); font-size: 14px; }\r
.dv-open-card .dv-btn { width: 100%; }\r
.dv-open-card .dv-error { color: var(--dv-danger); font-size: 13px; margin: 12px 0 0; }\r
.dv-drop { position: fixed; inset: 12px; z-index: 30; border-radius: 28px; border: 2px dashed var(--dv-primary); background: color-mix(in srgb, var(--dv-bg-top) 85%, transparent); display: grid; place-items: center; font-size: 17px; font-weight: 600; color: var(--dv-primary); pointer-events: none; }\r
\r
@media (max-width: 380px) {\r
  .dv-time { min-width: 0; font-size: 11px; }\r
  .dv-transport { gap: 6px; }\r
}</style>\r
</head>\r
<body class="dv-page">\r
<div id="dv-root"></div>\r
<script type="application/json" id="dshgo-data"><\/script>\r
<script>// dsh-go conversation viewer (docs/design/share-codes.md). One source,\r
// three ways a conversation arrives ([boot]):\r
//\r
//   - a \`.dshgo\` file picked or dropped on the landing page (site/share/);\r
//   - the app's \u300C\u5BFC\u51FA\u4E3A\u7F51\u9875\u300D: this script inlined into one self-contained\r
//     page with the file in it (app/tool/make_replay_viewer.py \u2192\r
//     app/lib/share_code/replay_viewer.g.dart);\r
//   - a hosted link \`https://<host>/c/<id>#k=<key>\`: the page fetches\r
//     \`/api/v1/c/<id>\` and decrypts it here with the key after \`#\`, which the\r
//     browser never sends (AES-256-GCM, \`DSG1\` + IV + ciphertext, gzip inside).\r
//\r
// Reads a conversation share code (deflate-raw + SHA-256 checksum, the same\r
// format as app/lib/share_code/share_codec.dart), checks the pictures against\r
// their names, then renders and replays it. Nothing is uploaded or stored;\r
// data only ever reaches the page as text nodes and data: URLs.\r
'use strict';\r
\r
(function (root) {\r
  // A non-browser runtime may expose a default navigator; keep tests in Chinese.\r
  var browserLanguage = typeof document !== 'undefined' && typeof navigator !== 'undefined' ? navigator.language || '' : '';\r
  var lang = !browserLanguage || /^zh/i.test(browserLanguage) ? 'zh' : 'en';\r
  if (typeof document !== 'undefined' && document.documentElement) document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';\r
  var I18N = {\r
    "zh": {\r
      "chat": "\u5BF9\u8BDD",\r
      "copy": "\u590D\u5236",\r
      "copied": "\u5DF2\u590D\u5236",\r
      "allText": "\u5168\u6587",\r
      "progress": "\u56DE\u653E\u8FDB\u5EA6",\r
      "speed": "\u500D\u901F",\r
      "openApp": "\u7528 dsh-go \u6253\u5F00",\r
      "download": "\u4E0B\u8F7D dsh-go",\r
      "saveChat": "\u5B58\u4E3A\u5BF9\u8BDD\u6587\u4EF6",\r
      "pause": "\u6682\u505C",\r
      "replay": "\u91CD\u65B0\u64AD\u653E",\r
      "play": "\u64AD\u653E",\r
      "goalResume": "\u76EE\u6807\u7EED\u8DD1",\r
      "schedule": "\u5B9A\u65F6\u4EFB\u52A1",\r
      "auto": "\u81EA\u52A8",\r
      "image": "\u56FE\u7247",\r
      "thinkingActive": "\u601D\u8003\u4E2D",\r
      "thinking": "\u601D\u8003",\r
      "interrupted": "\u5DF2\u4E2D\u65AD",\r
      "declined": "\u5DF2\u62D2\u7EDD",\r
      "failed": "\u5931\u8D25",\r
      "cancelled": "\u5DF2\u53D6\u6D88",\r
      "outputCut": "\u8F93\u51FA\uFF08\u5DF2\u622A\u65AD\uFF09",\r
      "output": "\u8F93\u51FA",\r
      "stopped": "\u5DF2\u505C\u6B62",\r
      "error": "\u51FA\u9519\u4E86",\r
      "completed": "\u5DF2\u5B8C\u6210",\r
      "allDone": "\u5168\u90E8\u5B8C\u6210",\r
      "now": "\u6B63\u5728\uFF1A",\r
      "next": "\u4E0B\u4E00\u6B65\uFF1A",\r
      "goal": "\u76EE\u6807",\r
      "paused": "\u5DF2\u6682\u505C",\r
      "blocked": "\u53D7\u963B",\r
      "achieved": "\u5DF2\u8FBE\u6210",\r
      "pickFile": "\u9009\u62E9\u6587\u4EF6",\r
      "viewChat": "\u67E5\u770B\u5BF9\u8BDD",\r
      "pickHint": "\u9009\u62E9\u6216\u62D6\u5165 .dshgo \u6587\u4EF6",\r
      "fileTooLarge": "\u6587\u4EF6\u592A\u5927",\r
      "drop": "\u677E\u624B\u6253\u5F00",\r
      "opening": "\u6B63\u5728\u6253\u5F00\u2026",\r
      "errorNewer": "\u9700\u8981\u66F4\u65B0 dsh-go \u624D\u80FD\u6253\u5F00",\r
      "errorBrowser": "\u8FD9\u4E2A\u6D4F\u89C8\u5668\u6253\u4E0D\u5F00\uFF0C\u6362\u4E2A\u65B0\u7248\u6D4F\u89C8\u5668\u8BD5\u8BD5",\r
      "errorKind": "\u8FD9\u4E0D\u662F\u5BF9\u8BDD\u6587\u4EF6",\r
      "errorGone": "\u94FE\u63A5\u5DF2\u8FC7\u671F\u6216\u88AB\u5220\u9664",\r
      "errorNetwork": "\u6CA1\u80FD\u6253\u5F00\uFF0C\u68C0\u67E5\u7F51\u7EDC\u540E\u91CD\u8BD5",\r
      "errorKey": "\u94FE\u63A5\u4E0D\u5B8C\u6574",\r
      "errorFormat": "\u8FD9\u4E2A\u6587\u4EF6\u4E0D\u5B8C\u6574\u6216\u5DF2\u635F\u574F",\r
      "seconds": "{n} \u79D2",\r
      "minutes": "{n} \u5206\u949F",\r
      "hours": "{n} \u5C0F\u65F6",\r
      "date": "{year} \u5E74 {month} \u6708 {day} \u65E5",\r
      "turnRangeOne": "\u7B2C {from} \u8F6E\uFF0C\u5171 {total} \u8F6E",\r
      "turnRange": "\u7B2C {from}\u2013{to} \u8F6E\uFF0C\u5171 {total} \u8F6E",\r
      "steps": "{n} \u6B65",\r
      "toolCalls": "{n} \u6B21\u5DE5\u5177\u8C03\u7528",\r
      "messages": "{n} \u6761\u6D88\u606F",\r
      "thoughts": "{n} \u6BB5\u601D\u8003",\r
      "tokenCount": "{count} tokens",\r
      "viewerTitle": "\u67E5\u770B\u5BF9\u8BDD \xB7 dsh-go"\r
    },\r
    "en": {\r
      "chat": "Chat",\r
      "copy": "Copy",\r
      "copied": "Copied",\r
      "allText": "Full text",\r
      "progress": "Replay progress",\r
      "speed": "Speed",\r
      "openApp": "Open in dsh-go",\r
      "download": "Download dsh-go",\r
      "saveChat": "Save chat file",\r
      "pause": "Pause",\r
      "replay": "Replay",\r
      "play": "Play",\r
      "goalResume": "Goal resumed",\r
      "schedule": "Automation",\r
      "auto": "Automatic",\r
      "image": "Image",\r
      "thinkingActive": "Thinking\u2026",\r
      "thinking": "Thinking",\r
      "interrupted": "Interrupted",\r
      "declined": "Declined",\r
      "failed": "Failed",\r
      "cancelled": "Cancelled",\r
      "outputCut": "Output (truncated)",\r
      "output": "Output",\r
      "stopped": "Stopped",\r
      "error": "Something went wrong",\r
      "completed": "Completed",\r
      "allDone": "All done",\r
      "now": "Now: ",\r
      "next": "Next: ",\r
      "goal": "Goal",\r
      "paused": "Paused",\r
      "blocked": "Blocked",\r
      "achieved": "Achieved",\r
      "pickFile": "Choose file",\r
      "viewChat": "View chat",\r
      "pickHint": "Choose or drop a .dshgo file",\r
      "fileTooLarge": "File is too large",\r
      "drop": "Drop to open",\r
      "opening": "Opening\u2026",\r
      "errorNewer": "Update dsh-go to open this",\r
      "errorBrowser": "Can\u2019t open this in your browser. Try a newer one.",\r
      "errorKind": "This isn\u2019t a chat file",\r
      "errorGone": "This link has expired or was deleted",\r
      "errorNetwork": "Couldn\u2019t open. Check your network and try again.",\r
      "errorKey": "This link is incomplete",\r
      "errorFormat": "This file is incomplete or damaged",\r
      "seconds": "{n} s",\r
      "minutes": "{n} min",\r
      "hours": "{n} h",\r
      "date": "{year}-{month}-{day}",\r
      "turnRangeOne": "Turn {from} of {total}",\r
      "turnRange": "Turns {from}\u2013{to} of {total}",\r
      "steps": {\r
        "one": "{n} step",\r
        "other": "{n} steps"\r
      },\r
      "toolCalls": {\r
        "one": "{n} tool call",\r
        "other": "{n} tool calls"\r
      },\r
      "messages": {\r
        "one": "{n} message",\r
        "other": "{n} messages"\r
      },\r
      "thoughts": {\r
        "one": "{n} thought",\r
        "other": "{n} thoughts"\r
      },\r
      "tokenCount": {\r
        "one": "{count} token",\r
        "other": "{count} tokens"\r
      },\r
      "viewerTitle": "View chat \xB7 dsh-go"\r
    }\r
  };\r
\r
  function tr(key, values) {\r
    var value = I18N[lang][key];\r
    values = values || {};\r
    if (typeof value === 'object') value = value[values.n === 1 ? 'one' : 'other'];\r
    return value.replace(/\\{(\\w+)\\}/g, function (_, name) { return values[name]; });\r
  }\r
\r
  var BODY_VERSION = 2;\r
  var SCHEMA = 1;\r
  var MAX_BODY = 16 * 1024 * 1024;\r
  var MAX_SMALL_BODY = 1024 * 1024;\r
  var MAX_ENTRIES = 20000;\r
  var MAX_TEXT = 400000;\r
  var MAX_TOOL_TEXT = 64000;\r
  var IMAGE_TYPES = { 'image/jpeg': 1, 'image/png': 1, 'image/webp': 1, 'image/gif': 1 };\r
\r
  // \u2500\u2500 Decoding \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  function b64urlToBytes(s) {\r
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('format');\r
    var padded = s.replace(/-/g, '+').replace(/_/g, '/');\r
    while (padded.length % 4) padded += '=';\r
    var bin;\r
    try { bin = atob(padded); } catch (e) { throw new Error('format'); }\r
    var out = new Uint8Array(bin.length);\r
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\r
    return out;\r
  }\r
\r
  function b64ToBytes(s) {\r
    var bin = atob(s);\r
    var out = new Uint8Array(bin.length);\r
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\r
    return out;\r
  }\r
\r
  function bytesToB64url(bytes) {\r
    var bin = '';\r
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);\r
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');\r
  }\r
\r
  async function inflate(bytes, limit) {\r
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));\r
    var reader = stream.getReader();\r
    var chunks = [];\r
    var total = 0;\r
    for (;;) {\r
      var r;\r
      try { r = await reader.read(); } catch (e) { throw new Error('format'); }\r
      if (r.done) break;\r
      total += r.value.length;\r
      if (total > limit) { reader.cancel(); throw new Error('format'); }\r
      chunks.push(r.value);\r
    }\r
    var out = new Uint8Array(total);\r
    var at = 0;\r
    chunks.forEach(function (c) { out.set(c, at); at += c.length; });\r
    return out;\r
  }\r
\r
  function canHash() { return !!(root.crypto && root.crypto.subtle); }\r
\r
  async function sha256(bytes) { return new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes)); }\r
\r
  /** The checked JSON object inside \`<data>.<sum>\`. Without SubtleCrypto\r
   *  (an old browser, a page opened from disk somewhere strict) the checksum\r
   *  can't be checked; [opts.trust] accepts the body then. */\r
  async function decodeCode(code, opts) {\r
    opts = opts || {};\r
    if (typeof DecompressionStream === 'undefined') throw new Error('browser');\r
    var parts = String(code).trim().split('.');\r
    if (parts.length !== 2 || !parts[0] || !/^[A-Za-z0-9_-]{8}$/.test(parts[1])) throw new Error('format');\r
    var body = await inflate(b64urlToBytes(parts[0]), MAX_BODY);\r
    if (canHash()) {\r
      if (bytesToB64url((await sha256(body)).slice(0, 6)) !== parts[1]) throw new Error('format');\r
    } else if (!opts.trust) {\r
      throw new Error('browser');\r
    }\r
    var json;\r
    try { json = JSON.parse(new TextDecoder().decode(body)); } catch (e) { throw new Error('format'); }\r
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('format');\r
    if (body.length > MAX_SMALL_BODY && json.kind !== 'conversation') throw new Error('format');\r
    return json;\r
  }\r
\r
  /** A \`.dshgo\` file's text (or a bare code): {code, kind, name, assets}. */\r
  function readEnvelope(text) {\r
    var t = String(text).trim();\r
    if (t.charAt(0) !== '{') return { code: t, assets: null };\r
    var json;\r
    try { json = JSON.parse(t); } catch (e) { throw new Error('format'); }\r
    if (!json || typeof json.dshgo !== 'number' || typeof json.code !== 'string') throw new Error('format');\r
    return {\r
      code: json.code,\r
      kind: typeof json.kind === 'string' ? json.kind : null,\r
      name: typeof json.name === 'string' ? json.name : null,\r
      assets: json.assets && typeof json.assets === 'object' ? json.assets : null\r
    };\r
  }\r
\r
  function num(v) { return typeof v === 'number' && isFinite(v) && v >= 0 ? Math.round(v) : null; }\r
\r
  function str(v, max) {\r
    if (typeof v !== 'string' || !v) return null;\r
    return v.length <= max ? v : v.slice(0, max) + '\u2026';\r
  }\r
\r
  function line(v, max) {\r
    if (typeof v !== 'string') return null;\r
    var t = v.replace(/\\s+/g, ' ').trim();\r
    if (!t) return null;\r
    return t.length <= max ? t : t.slice(0, max - 1) + '\u2026';\r
  }\r
\r
  function readEntry(e) {\r
    if (!e || typeof e !== 'object') throw new Error('format');\r
    var t = num(e.t) || 0;\r
    var d = num(e.d);\r
    switch (e.type) {\r
      case 'turn': return { type: 'turn', t: t, d: d, end: str(e.end, 32), steps: num(e.steps), tokens: num(e.tokens) };\r
      case 'user':\r
        return {\r
          type: 'user', t: t, text: str(e.text, MAX_TEXT) || '', source: str(e.source, 32),\r
          images: (Array.isArray(e.images) ? e.images.slice(0, 20) : []).filter(function (i) {\r
            return i && typeof i.id === 'string' && /^[A-Za-z0-9_-]{8,32}$/.test(i.id);\r
          }).map(function (i) { return { id: i.id, w: num(i.w), h: num(i.h), name: str(i.name, 200) }; }),\r
          files: (Array.isArray(e.files) ? e.files.slice(0, 20) : []).filter(function (f) {\r
            return f && str(f.name, 200);\r
          }).map(function (f) { return { name: str(f.name, 200), size: num(f.size) }; })\r
        };\r
      case 'reply':\r
        return { type: 'reply', t: t, d: d, text: str(e.text, MAX_TEXT) || '', think: str(e.think, MAX_TEXT), plain: str(e.plain, MAX_TEXT), model: str(e.model, 80), cut: e.cut === true };\r
      case 'tool':\r
        return {\r
          type: 'tool', t: t, d: d, name: str(e.name, 80) || 'tool', summary: str(e.summary, 500) || '', verb: str(e.verb, 40),\r
          status: ({ failed: 1, denied: 1, cancelled: 1 })[e.status] ? e.status : 'ok',\r
          result: str(e.result, MAX_TOOL_TEXT), more: num(e.more) || 0, error: str(e.error, 2000),\r
          args: e.args && typeof e.args === 'object' && !Array.isArray(e.args) ? e.args : {}\r
        };\r
      case 'notice': return { type: 'notice', t: t, kind: str(e.kind, 32) || 'error', text: str(e.text, 4000) || '' };\r
      case 'todos':\r
        return {\r
          type: 'todos', t: t,\r
          items: (Array.isArray(e.items) ? e.items.slice(0, 200) : []).filter(function (i) { return i && str(i.text, 500); })\r
            .map(function (i) { return { text: str(i.text, 500), status: str(i.status, 20) || 'pending' }; })\r
        };\r
      case 'goal': return { type: 'goal', t: t, text: str(e.text, 4000), phase: str(e.phase, 20) };\r
      case 'command': return { type: 'command', t: t, line: str(e.line, 2000) || '/', ok: e.ok !== false, text: str(e.text, 8000) };\r
      default: return null;\r
    }\r
  }\r
\r
  /** Validates a decoded conversation body (as ConversationShare.fromJson). */\r
  function readConversation(json) {\r
    if (typeof json.v !== 'number' || json.v < 1) throw new Error('format');\r
    if (json.v > BODY_VERSION) throw new Error('newer');\r
    if (json.kind !== 'conversation') throw new Error('kind');\r
    if (typeof json.schema !== 'number' || json.schema < 1) throw new Error('format');\r
    if (json.schema > SCHEMA) throw new Error('newer');\r
    var start = typeof json.start === 'string' ? Date.parse(json.start) : NaN;\r
    if (isNaN(start)) throw new Error('format');\r
    if (!Array.isArray(json.entries) || json.entries.length > MAX_ENTRIES) throw new Error('format');\r
    var entries = [];\r
    json.entries.forEach(function (e) { var r = readEntry(e); if (r) entries.push(r); });\r
    var range = json.range && num(json.range.from) && num(json.range.to) && num(json.range.of) ? json.range : null;\r
    return {\r
      title: line(json.title, 120) || tr('chat'),\r
      model: line(json.model, 80),\r
      app: line(json.app, 40),\r
      start: start,\r
      created: typeof json.created === 'string' ? Date.parse(json.created) : NaN,\r
      range: range,\r
      entries: entries\r
    };\r
  }\r
\r
  /** Pictures from \`assets\` that the conversation uses and whose bytes match\r
   *  their names, as data: URLs. */\r
  async function readAssets(raw, conv, opts) {\r
    var out = {};\r
    if (!raw) return out;\r
    var wanted = {};\r
    conv.entries.forEach(function (e) { if (e.type === 'user') e.images.forEach(function (i) { wanted[i.id] = 1; }); });\r
    var ids = Object.keys(raw);\r
    for (var k = 0; k < ids.length; k++) {\r
      var id = ids[k];\r
      var a = raw[id];\r
      if (!wanted[id] || !a || !IMAGE_TYPES[a.type] || typeof a.data !== 'string') continue;\r
      var bytes;\r
      try { bytes = b64ToBytes(a.data); } catch (e) { continue; }\r
      if (canHash()) {\r
        if (bytesToB64url((await sha256(bytes)).slice(0, 9)) !== id) continue;\r
      } else if (!(opts && opts.trust)) {\r
        continue;\r
      }\r
      out[id] = 'data:' + a.type + ';base64,' + a.data;\r
    }\r
    return out;\r
  }\r
\r
  /** A conversation from a \`.dshgo\` file's text (or a bare code). */\r
  async function openFile(text, opts) {\r
    var env = readEnvelope(text);\r
    var json = await decodeCode(env.code, opts);\r
    var conv = readConversation(json);\r
    return { conversation: conv, assets: await readAssets(env.assets, conv, opts), code: env.code };\r
  }\r
\r
\r
  // \u2500\u2500 Hosted links \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var MAGIC = [0x44, 0x53, 0x47, 0x31]; // "DSG1"\r
\r
  /** The \`.dshgo\` text inside a hosted blob: \`DSG1\` + 12-byte IV + AES-GCM\r
   *  ciphertext (tag included) of the gzipped file. */\r
  async function decryptHosted(buffer, keyText) {\r
    var bytes = new Uint8Array(buffer);\r
    if (bytes.length < 4 + 12 + 16) throw new Error('format');\r
    for (var i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) throw new Error('format');\r
    if (!canHash() || typeof DecompressionStream === 'undefined') throw new Error('browser');\r
    var raw;\r
    try { raw = b64urlToBytes(String(keyText || '')); } catch (e) { throw new Error('key'); }\r
    if (raw.length !== 32) throw new Error('key');\r
    var key = await root.crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);\r
    var plain;\r
    try {\r
      plain = await root.crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(4, 16) }, key, bytes.slice(16));\r
    } catch (e) {\r
      throw new Error('key');\r
    }\r
    var text;\r
    try {\r
      var stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));\r
      text = await new Response(stream).text();\r
    } catch (e) {\r
      throw new Error('format');\r
    }\r
    if (text.length > 64 * 1024 * 1024) throw new Error('format');\r
    return text;\r
  }\r
\r
  /** Fetches and opens a hosted conversation. */\r
  async function openHosted(id, keyText, fetchImpl) {\r
    var res;\r
    try {\r
      res = await (fetchImpl || root.fetch.bind(root))('/api/v1/c/' + encodeURIComponent(id), {\r
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'\r
      });\r
    } catch (e) {\r
      throw new Error('network');\r
    }\r
    if (res.status === 404 || res.status === 410) throw new Error('gone');\r
    if (!res.ok) throw new Error('network');\r
    var text = await decryptHosted(await res.arrayBuffer(), keyText);\r
    var opened = await openFile(text);\r
    opened.fileText = text;\r
    return opened;\r
  }\r
\r
  // \u2500\u2500 Replay pacing (app/lib/ui/replay/replay_timeline.dart) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var PACE = {\r
    gapKnee: 500, gapRate: 0.2, maxGap: 1600, maxGapBeforePrompt: 900,\r
    minStagger: 120, maxStagger: 400,\r
    fastestCps: 500, slowestCps: 30, maxStream: 6000, minStream: 300, assumedCps: 80,\r
    minThinking: 600, maxThinking: 2400,\r
    toolKnee: 300, toolRate: 0.15, minTool: 250, maxTool: 2500, assumedTool: 400,\r
    turnTail: 150\r
  };\r
\r
  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }\r
  function chars(s) { return s ? Array.from(s).length : 0; }\r
\r
  function gap(g, cap) {\r
    if (g <= 0) return 0;\r
    if (g <= PACE.gapKnee) return Math.min(g, cap);\r
    return Math.min(cap, PACE.gapKnee + (g - PACE.gapKnee) * PACE.gapRate);\r
  }\r
\r
  function origRun(e) { return (e.type === 'reply' || e.type === 'tool') ? (e.d || 0) : 0; }\r
\r
  function durations(e) {\r
    if (e.type === 'reply') {\r
      var textChars = chars(e.text);\r
      var thinkChars = chars(e.think);\r
      var total = textChars + thinkChars;\r
      if (total === 0) return [0, 0];\r
      var orig = e.d != null ? e.d : total / PACE.assumedCps * 1000;\r
      var thinkOrig = orig * thinkChars / total;\r
      var textOrig = orig - thinkOrig;\r
      var think = thinkChars === 0 ? 0 : clamp(thinkOrig, PACE.minThinking, PACE.maxThinking);\r
      if (textChars === 0) return [think, 0];\r
      var fastest = textChars / PACE.fastestCps * 1000;\r
      var slowest = textChars / PACE.slowestCps * 1000;\r
      var run = Math.min(PACE.maxStream, Math.max(fastest, Math.min(textOrig, slowest)));\r
      return [think, Math.max(run, PACE.minStream)];\r
    }\r
    if (e.type === 'tool') {\r
      if (e.d == null) return [0, PACE.assumedTool];\r
      var r = e.d <= PACE.toolKnee ? e.d : PACE.toolKnee + (e.d - PACE.toolKnee) * PACE.toolRate;\r
      return [0, clamp(r, PACE.minTool, PACE.maxTool)];\r
    }\r
    return [0, 0];\r
  }\r
\r
  /** {beats: [{start, think, end}], turnEnds: {index: time}, duration}. */\r
  function timeline(entries) {\r
    var beats = [];\r
    var lastEndOrig = 0, lastEndV = 0, prevStartOrig = 0, prevStartV = 0;\r
    entries.forEach(function (e, i) {\r
      var t = e.t;\r
      var dur = durations(e);\r
      var start;\r
      if (i === 0) start = 0;\r
      else if (t >= lastEndOrig) start = lastEndV + gap(t - lastEndOrig, e.type === 'user' || e.type === 'turn' ? PACE.maxGapBeforePrompt : PACE.maxGap);\r
      else start = prevStartV + clamp(t - prevStartOrig, PACE.minStagger, PACE.maxStagger);\r
      start = Math.max(start, prevStartV);\r
      var beat = { start: start, think: start + dur[0], end: start + dur[0] + dur[1] };\r
      beats.push(beat);\r
      prevStartOrig = t;\r
      prevStartV = start;\r
      if (e.type !== 'turn') {\r
        lastEndOrig = Math.max(lastEndOrig, t + origRun(e));\r
        lastEndV = Math.max(lastEndV, beat.end);\r
      }\r
    });\r
    var turnEnds = {};\r
    entries.forEach(function (e, i) {\r
      if (e.type !== 'turn' || e.d == null) return;\r
      var close = e.t + e.d;\r
      var end = beats[i].start;\r
      for (var j = i + 1; j < entries.length && entries[j].type !== 'turn'; j++) {\r
        if (entries[j].t > close) break;\r
        end = Math.max(end, beats[j].end);\r
      }\r
      turnEnds[i] = end + PACE.turnTail;\r
    });\r
    var duration = 0;\r
    beats.forEach(function (b) { duration = Math.max(duration, b.end); });\r
    Object.keys(turnEnds).forEach(function (k) { duration = Math.max(duration, turnEnds[k]); });\r
    return { beats: beats, turnEnds: turnEnds, duration: duration };\r
  }\r
\r
  // \u2500\u2500 DOM helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  function el(tag, cls, text) {\r
    var n = document.createElement(tag);\r
    if (cls) n.className = cls;\r
    if (text != null) n.textContent = text;\r
    return n;\r
  }\r
\r
  var SVG_NS = 'http://www.w3.org/2000/svg';\r
  var ICONS = {\r
    play: 'M8 5.6v12.8c0 .8.9 1.3 1.6.9l10-6.4c.6-.4.6-1.3 0-1.7l-10-6.4C8.9 4.3 8 4.8 8 5.6Z',\r
    pause: 'M7 5h3a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm7 0h3a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1h-3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z',\r
    replay: 'M12 5a7 7 0 1 1-7 7 1 1 0 1 1 2 0 5 5 0 1 0 1.6-3.7l1.1 1.1A.6.6 0 0 1 9.3 10.4H5.6A.6.6 0 0 1 5 9.8V6.1a.6.6 0 0 1 1-.4l1.2 1.2A7 7 0 0 1 12 5Z',\r
    chevron: 'M6.3 9.3a1 1 0 0 1 1.4 0L12 13.6l4.3-4.3a1 1 0 1 1 1.4 1.4l-5 5a1 1 0 0 1-1.4 0l-5-5a1 1 0 0 1 0-1.4Z',\r
    check: 'M9.5 16.2 5.8 12.5a1 1 0 0 0-1.4 1.4l4.4 4.4a1 1 0 0 0 1.4 0l9.6-9.6a1 1 0 0 0-1.4-1.4l-8.9 8.9Z',\r
    think: 'M12 3a6 6 0 0 0-3.6 10.8c.4.3.6.8.6 1.3V16a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1v-.9c0-.5.2-1 .6-1.3A6 6 0 0 0 12 3Zm-2 16a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2h-4Z',\r
    terminal: 'M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Zm2.3 4.3a1 1 0 0 0 0 1.4L9.6 12l-2.3 2.3a1 1 0 1 0 1.4 1.4l3-3a1 1 0 0 0 0-1.4l-3-3a1 1 0 0 0-1.4 0ZM13 14a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2h-4Z',\r
    read: 'M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm2 9a1 1 0 0 0 0 2h6a1 1 0 0 0 0-2H9Zm0 4a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2H9Z',\r
    edit: 'M16.6 3.6a2 2 0 0 1 2.8 0l1 1a2 2 0 0 1 0 2.8L9.8 18 5 19l1-4.8L16.6 3.6Z',\r
    search: 'M10.5 4a6.5 6.5 0 0 1 5.2 10.4l3.9 3.9a1 1 0 0 1-1.4 1.4l-3.9-3.9A6.5 6.5 0 1 1 10.5 4Zm0 2a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z',\r
    web: 'M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18Zm-2.3 2.4A7 7 0 0 0 5.1 11h3a14 14 0 0 1 1.6-5.6Zm4.6 0A14 14 0 0 1 15.9 11h3a7 7 0 0 0-4.6-5.6ZM12 5.2A12 12 0 0 0 10.1 11h3.8A12 12 0 0 0 12 5.2ZM5.1 13a7 7 0 0 0 4.6 5.6A14 14 0 0 1 8.1 13h-3Zm5 0a12 12 0 0 0 1.9 5.8 12 12 0 0 0 1.9-5.8h-3.8Zm5.8 0a14 14 0 0 1-1.6 5.6 7 7 0 0 0 4.6-5.6h-3Z',\r
    agent: 'M12 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM6 14a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm12 0a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm-7-4h2v2.4l3.6 2.1-1 1.7L12 14l-3.6 2.2-1-1.7 3.6-2.1V10Z',\r
    plan: 'M9 4h6a1 1 0 0 1 1 1h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2a1 1 0 0 1 1-1Zm6.7 7.3a1 1 0 0 0-1.4 0L11 14.6l-1.3-1.3a1 1 0 0 0-1.4 1.4l2 2a1 1 0 0 0 1.4 0l4-4a1 1 0 0 0 0-1.4Z',\r
    tool: 'M14.7 3.3a5 5 0 0 0-5.6 6.9l-5.4 5.4a2 2 0 0 0 0 2.8l.9.9a2 2 0 0 0 2.8 0l5.4-5.4a5 5 0 0 0 6.9-5.6l-2.6 2.6-2.8-.7-.7-2.8 2.6-2.6Z',\r
    warn: 'M12 3.5c.7 0 1.3.4 1.7 1l7.1 12.4c.8 1.3-.2 3.1-1.7 3.1H4.9c-1.5 0-2.5-1.8-1.7-3.1L10.3 4.5c.4-.6 1-1 1.7-1Zm0 5a1 1 0 0 0-1 1v4a1 1 0 0 0 2 0v-4a1 1 0 0 0-1-1Zm0 7.5a1.2 1.2 0 1 0 0 2.4 1.2 1.2 0 0 0 0-2.4Z',\r
    file: 'M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm6 1.5V8a1 1 0 0 0 1 1h3.5L13 4.5Z',\r
    flag: 'M6 3a1 1 0 0 1 1 1v.3C8.2 3.8 9.8 3.6 12 4.4c2.6 1 4.4.6 6-.2a1 1 0 0 1 1.4.9v9a1 1 0 0 1-.6.9c-2 1-4.3 1.4-7.4.3-2.2-.8-3.9-.6-5.4.1V20a1 1 0 0 1-2 0V4a1 1 0 0 1 1-1Z'\r
  };\r
\r
  function icon(name, cls) {\r
    var svg = document.createElementNS(SVG_NS, 'svg');\r
    svg.setAttribute('viewBox', '0 0 24 24');\r
    svg.setAttribute('aria-hidden', 'true');\r
    if (cls) svg.setAttribute('class', cls);\r
    var path = document.createElementNS(SVG_NS, 'path');\r
    path.setAttribute('d', ICONS[name] || ICONS.tool);\r
    svg.appendChild(path);\r
    return svg;\r
  }\r
\r
  // \u2500\u2500 Markdown (a safe subset; streaming-tolerant) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var SAFE_URL = /^(https?:|mailto:)/i;\r
\r
  function inline(text, parent) {\r
    // Code spans first, then emphasis / links in the rest.\r
    var re = /(\`+)([\\s\\S]*?[^\`])\\1(?!\`)|\\*\\*([^*\\n]+)\\*\\*|__([^_\\n]+)__|~~([^~\\n]+)~~|\\*([^*\\s][^*\\n]*?)\\*|(?:^|(?<=[\\s(]))_([^_\\s][^_\\n]*?)_(?=$|[\\s).,!?;:])|\\[([^\\]\\n]+)\\]\\(([^()\\s]+)(?:\\s+"[^"]*")?\\)|(https?:\\/\\/[^\\s<>()]+[^\\s<>().,;:!?'"])|\\$([^$\\n]+)\\$/g;\r
    var at = 0;\r
    var m;\r
    while ((m = re.exec(text))) {\r
      if (m.index > at) parent.appendChild(document.createTextNode(text.slice(at, m.index)));\r
      if (m[1]) parent.appendChild(el('code', null, m[2]));\r
      else if (m[3] || m[4]) { var b = el('strong'); inline(m[3] || m[4], b); parent.appendChild(b); }\r
      else if (m[5]) { var s = el('del'); inline(m[5], s); parent.appendChild(s); }\r
      else if (m[6] || m[7]) { var i = el('em'); inline(m[6] || m[7], i); parent.appendChild(i); }\r
      else if (m[8]) {\r
        if (SAFE_URL.test(m[9])) {\r
          var a = el('a');\r
          a.href = m[9];\r
          a.target = '_blank';\r
          a.rel = 'noopener noreferrer nofollow';\r
          inline(m[8], a);\r
          parent.appendChild(a);\r
        } else {\r
          inline(m[8], parent);\r
        }\r
      } else if (m[10]) {\r
        var link = el('a', null, m[10]);\r
        link.href = m[10];\r
        link.target = '_blank';\r
        link.rel = 'noopener noreferrer nofollow';\r
        parent.appendChild(link);\r
      } else if (m[11]) parent.appendChild(el('span', 'dv-math', m[11]));\r
      at = re.lastIndex;\r
    }\r
    if (at < text.length) parent.appendChild(document.createTextNode(text.slice(at)));\r
  }\r
\r
  function paragraph(lines, parent) {\r
    var p = el('p');\r
    lines.forEach(function (l, i) {\r
      if (i > 0) p.appendChild(/ {2,}$|\\\\$/.test(lines[i - 1]) ? el('br') : document.createTextNode('\\n'));\r
      inline(l.replace(/\\\\$/, '').replace(/ {2,}$/, ''), p);\r
    });\r
    parent.appendChild(p);\r
  }\r
\r
  function splitRow(row) {\r
    var t = row.trim().replace(/^\\|/, '').replace(/\\|$/, '');\r
    return t.split(/(?<!\\\\)\\|/).map(function (c) { return c.trim().replace(/\\\\\\|/g, '|'); });\r
  }\r
\r
  function table(rows, parent) {\r
    var t = el('table');\r
    var head = el('thead');\r
    var tr = el('tr');\r
    splitRow(rows[0]).forEach(function (c) { var th = el('th'); inline(c, th); tr.appendChild(th); });\r
    head.appendChild(tr);\r
    t.appendChild(head);\r
    var body = el('tbody');\r
    rows.slice(2).forEach(function (r) {\r
      var row = el('tr');\r
      splitRow(r).forEach(function (c) { var td = el('td'); inline(c, td); row.appendChild(td); });\r
      body.appendChild(row);\r
    });\r
    t.appendChild(body);\r
    parent.appendChild(t);\r
  }\r
\r
  function list(lines, parent) {\r
    // lines: [{indent, ordered, text, start}]\r
    var stack = [];\r
    lines.forEach(function (item) {\r
      while (stack.length && item.indent < stack[stack.length - 1].indent) stack.pop();\r
      var top = stack[stack.length - 1];\r
      if (!top || item.indent > top.indent) {\r
        var listEl = el(item.ordered ? 'ol' : 'ul');\r
        if (item.ordered && item.start > 1) listEl.start = item.start;\r
        if (top && top.lastLi) top.lastLi.appendChild(listEl); else parent.appendChild(listEl);\r
        top = { indent: item.indent, el: listEl, lastLi: null };\r
        stack.push(top);\r
      }\r
      var li = el('li');\r
      inline(item.text, li);\r
      top.el.appendChild(li);\r
      top.lastLi = li;\r
    });\r
  }\r
\r
  function markdown(src, parent) {\r
    var lines = String(src).replace(/\\r\\n?/g, '\\n').split('\\n');\r
    var i = 0;\r
    var para = [];\r
    function flush() { if (para.length) { paragraph(para, parent); para = []; } }\r
    while (i < lines.length) {\r
      var l = lines[i];\r
      var fence = /^\\s{0,3}(\`{3,}|~{3,})\\s*([^\`\\s]*)?.*$/.exec(l);\r
      if (fence) {\r
        flush();\r
        var mark = fence[1];\r
        var lang = (fence[2] || '').toLowerCase();\r
        var body = [];\r
        i++;\r
        while (i < lines.length && !(lines[i].trim().indexOf(mark.charAt(0) === '\`' ? '\`\`\`' : '~~~') === 0 && lines[i].trim().replace(/[\`~]/g, '') === '')) {\r
          body.push(lines[i]);\r
          i++;\r
        }\r
        i++;\r
        if (lang === 'math' || lang === 'latex') { var mb = el('p', 'dv-math', body.join('\\n')); mb.style.whiteSpace = 'pre-wrap'; parent.appendChild(mb); }\r
        else parent.appendChild(codeBlock(body.join('\\n'), lang));\r
        continue;\r
      }\r
      if (/^\\s*\\$\\$\\s*$/.test(l)) {\r
        flush();\r
        var math = [];\r
        i++;\r
        while (i < lines.length && !/^\\s*\\$\\$\\s*$/.test(lines[i])) { math.push(lines[i]); i++; }\r
        i++;\r
        var mp = el('p', 'dv-math', math.join('\\n'));\r
        mp.style.whiteSpace = 'pre-wrap';\r
        parent.appendChild(mp);\r
        continue;\r
      }\r
      if (!l.trim()) { flush(); i++; continue; }\r
      var h = /^\\s{0,3}(#{1,6})\\s+(.*?)\\s*#*\\s*$/.exec(l);\r
      if (h) { flush(); var he = el('h' + h[1].length); inline(h[2], he); parent.appendChild(he); i++; continue; }\r
      if (/^\\s{0,3}([-*_])(\\s*\\1){2,}\\s*$/.test(l)) { flush(); parent.appendChild(el('hr')); i++; continue; }\r
      if (/^\\s{0,3}>/.test(l)) {\r
        flush();\r
        var quote = [];\r
        while (i < lines.length && /^\\s{0,3}>/.test(lines[i])) { quote.push(lines[i].replace(/^\\s{0,3}>\\s?/, '')); i++; }\r
        var bq = el('blockquote');\r
        markdown(quote.join('\\n'), bq);\r
        parent.appendChild(bq);\r
        continue;\r
      }\r
      if (/^\\s*\\|.*\\|\\s*$/.test(l) && i + 1 < lines.length && /^\\s*\\|?\\s*:?-{2,}:?\\s*(\\|\\s*:?-{2,}:?\\s*)*\\|?\\s*$/.test(lines[i + 1])) {\r
        flush();\r
        var rows = [];\r
        while (i < lines.length && /^\\s*\\|.*\\|?\\s*$/.test(lines[i]) && lines[i].trim()) { rows.push(lines[i]); i++; }\r
        table(rows, parent);\r
        continue;\r
      }\r
      var li = /^(\\s*)([-*+]|(\\d{1,9})[.)])\\s+(.*)$/.exec(l);\r
      if (li) {\r
        flush();\r
        var items = [];\r
        while (i < lines.length) {\r
          var m = /^(\\s*)([-*+]|(\\d{1,9})[.)])\\s+(.*)$/.exec(lines[i]);\r
          if (m) {\r
            items.push({ indent: m[1].replace(/\\t/g, '    ').length, ordered: !!m[3], start: m[3] ? parseInt(m[3], 10) : 1, text: m[4] });\r
            i++;\r
          } else if (lines[i].trim() && /^\\s{2,}/.test(lines[i]) && items.length) {\r
            items[items.length - 1].text += ' ' + lines[i].trim();\r
            i++;\r
          } else break;\r
        }\r
        list(items, parent);\r
        continue;\r
      }\r
      para.push(l);\r
      i++;\r
    }\r
    flush();\r
  }\r
\r
  /** Text cut mid-stream, closed for display: an open code span or bold. */\r
  function repairStream(text) {\r
    var lines = text.split('\\n');\r
    var fences = 0;\r
    lines.forEach(function (l) { if (/^\\s{0,3}(\`\`\`|~~~)/.test(l)) fences++; });\r
    if (fences % 2) return text; // inside a code block: shown as code already\r
    var last = lines[lines.length - 1];\r
    var ticks = (last.match(/\`/g) || []).length;\r
    if (ticks % 2) last += '\`';\r
    var stars = (last.match(/\\*\\*/g) || []).length;\r
    if (stars % 2) last += '**';\r
    lines[lines.length - 1] = last;\r
    return lines.join('\\n');\r
  }\r
\r
  /** The streaming caret at the end of the last text, however deep. */\r
  function caret(root) {\r
    var node = root;\r
    // Down through blocks only (the text after a bold run belongs to its\r
    // paragraph, not to the run).\r
    while (node.lastElementChild && /^(P|LI|OL|UL|BLOCKQUOTE|H[1-6]|DIV)$/.test(node.lastElementChild.tagName)) {\r
      node = node.lastElementChild;\r
    }\r
    if (node.classList.contains('dv-code')) node = node.querySelector('code') || node;\r
    node.appendChild(el('span', 'dv-caret'));\r
  }\r
\r
  // \u2500\u2500 Code highlighting (keywords, strings, comments, numbers) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var KW = {\r
    js: 'async await break case catch class const continue debugger default delete do else export extends finally for from function if import in instanceof let new of return static super switch this throw try typeof var void while with yield interface type enum implements private public protected readonly as',\r
    dart: 'abstract as assert async await break case catch class const continue default do else enum export extends extension external factory final finally for get if implements import in is late library mixin new on operator part required return sealed set static super switch sync this throw try typedef var void when while with yield base interface',\r
    py: 'and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case',\r
    sh: 'if then else elif fi for while do done case esac in function return export local readonly source echo cd exit set unset',\r
    go: 'break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var',\r
    rust: 'as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while',\r
    c: 'auto break case char class const continue default do double else enum extern float for goto if inline int long namespace new private protected public return short signed sizeof static struct switch template this throw try typedef typename union unsigned using virtual void volatile while bool fun val var when object package import override suspend data sealed is in out let guard func struct protocol extension',\r
    sql: 'select from where and or not insert into values update set delete create table alter drop index join left right inner outer on group by order having limit offset as distinct union all null is in like between case when then else end primary key references',\r
    css: 'important',\r
    yaml: 'true false null yes no on off'\r
  };\r
  var LIT = { 'true': 1, 'false': 1, 'null': 1, 'undefined': 1, 'None': 1, 'True': 1, 'False': 1, 'nil': 1 };\r
  var ALIAS = {\r
    javascript: 'js', jsx: 'js', ts: 'js', typescript: 'js', tsx: 'js', mjs: 'js', cjs: 'js', json: 'js', jsonc: 'js',\r
    python: 'py', py3: 'py', bash: 'sh', shell: 'sh', zsh: 'sh', console: 'sh', sh: 'sh', fish: 'sh', ps1: 'sh', powershell: 'sh',\r
    golang: 'go', rs: 'rust', cpp: 'c', 'c++': 'c', h: 'c', hpp: 'c', cs: 'c', csharp: 'c', java: 'c', kotlin: 'c', kt: 'c', swift: 'c', scala: 'c', php: 'c',\r
    yml: 'yaml', scss: 'css', less: 'css', postgres: 'sql', mysql: 'sql', sqlite: 'sql', dart: 'dart', go: 'go', rust: 'rust', c: 'c', sql: 'sql', css: 'css', yaml: 'yaml', js: 'js'\r
  };\r
\r
  function highlight(code, lang, parent) {\r
    var family = ALIAS[lang] || null;\r
    if (lang === 'diff' || lang === 'patch') {\r
      code.split('\\n').forEach(function (l, i) {\r
        if (i > 0) parent.appendChild(document.createTextNode('\\n'));\r
        var cls = /^\\+(?!\\+\\+)/.test(l) ? 'dv-add' : /^-(?!--)/.test(l) ? 'dv-del' : /^@@/.test(l) ? 'dv-t' : null;\r
        parent.appendChild(cls ? el('span', cls, l) : document.createTextNode(l));\r
      });\r
      return;\r
    }\r
    if (!family || code.length > 60000) { parent.textContent = code; return; }\r
    var hash = family === 'py' || family === 'sh' || family === 'yaml';\r
    var slash = family !== 'py' && family !== 'sh' && family !== 'yaml' && family !== 'sql';\r
    var words = {};\r
    (KW[family] || '').split(' ').forEach(function (w) { words[w] = 1; });\r
    var ci = family === 'sql';\r
    var re = new RegExp([\r
      slash ? '\\\\/\\\\/[^\\\\n]*|\\\\/\\\\*[\\\\s\\\\S]*?(?:\\\\*\\\\/|$)' : null,\r
      hash ? '#[^\\\\n]*' : null,\r
      family === 'sql' ? '--[^\\\\n]*' : null,\r
      family === 'py' ? '"""[\\\\s\\\\S]*?(?:"""|$)|\\'\\'\\'[\\\\s\\\\S]*?(?:\\'\\'\\'|$)' : null,\r
      '"(?:[^"\\\\\\\\\\\\n]|\\\\\\\\.)*"?|\\'(?:[^\\'\\\\\\\\\\\\n]|\\\\\\\\.)*\\'?|\`(?:[^\`\\\\\\\\]|\\\\\\\\.)*\`?',\r
      '\\\\b\\\\d[\\\\d_]*(?:\\\\.\\\\d+)?(?:[eE][+-]?\\\\d+)?\\\\b|\\\\b0x[\\\\da-fA-F]+\\\\b',\r
      '[A-Za-z_$][\\\\w$]*'\r
    ].filter(Boolean).join('|'), 'g');\r
    var at = 0;\r
    var m;\r
    while ((m = re.exec(code))) {\r
      if (m.index > at) parent.appendChild(document.createTextNode(code.slice(at, m.index)));\r
      var t = m[0];\r
      var c0 = t.charAt(0);\r
      var cls = null;\r
      if ((slash && (t.indexOf('//') === 0 || t.indexOf('/*') === 0)) || (hash && c0 === '#') || (family === 'sql' && t.indexOf('--') === 0)) cls = 'dv-c';\r
      else if (c0 === '"' || c0 === "'" || c0 === '\`') cls = 'dv-s';\r
      else if (/^\\d|^0x/.test(t)) cls = 'dv-n';\r
      else if (words[ci ? t.toLowerCase() : t]) cls = 'dv-k';\r
      else if (LIT[t]) cls = 'dv-n';\r
      else if (/^[A-Z]/.test(t) && family !== 'sh') cls = 'dv-t';\r
      else if (code.charAt(re.lastIndex) === '(') cls = 'dv-f';\r
      parent.appendChild(cls ? el('span', cls, t) : document.createTextNode(t));\r
      at = re.lastIndex;\r
    }\r
    if (at < code.length) parent.appendChild(document.createTextNode(code.slice(at)));\r
  }\r
\r
  function codeBlock(code, lang) {\r
    var wrap = el('div', 'dv-code');\r
    var head = el('div', 'dv-code-head');\r
    head.appendChild(el('span', null, lang || 'text'));\r
    var copy = el('button', null, tr('copy'));\r
    copy.type = 'button';\r
    copy.addEventListener('click', function () {\r
      if (typeof navigator !== 'undefined' && navigator.clipboard) navigator.clipboard.writeText(code).then(function () {\r
        copy.textContent = tr('copied');\r
        setTimeout(function () { copy.textContent = tr('copy'); }, 1400);\r
      }, function () {});\r
    });\r
    head.appendChild(copy);\r
    wrap.appendChild(head);\r
    var pre = el('pre');\r
    var c = el('code');\r
    highlight(code, lang, c);\r
    pre.appendChild(c);\r
    wrap.appendChild(pre);\r
    return wrap;\r
  }\r
\r
  // \u2500\u2500 Formatting \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var TONES = {\r
    bash: 0, pwsh: 0, job_output: 0, job_list: 0, job_kill: 0,\r
    read: 1, read_image: 1, present: 1,\r
    write: 2, edit: 2, str_replace_editor: 2,\r
    grep: 3, glob: 3, web_fetch: 4, web_search: 4,\r
    subagent: 5, send_message: 5, interrupt_agent: 5, workflow: 5, ralph: 5, skill: 5,\r
    todo_write: 6, create_goal: 6, get_goal: 6, update_goal: 6, ask_user_question: 6\r
  };\r
  var TONE_ICON = ['terminal', 'read', 'edit', 'search', 'web', 'agent', 'plan', 'tool'];\r
  var CODE_TOOLS = { bash: 1, pwsh: 1, read: 1, write: 1, edit: 1, str_replace_editor: 1, read_image: 1, grep: 1, glob: 1, job_output: 1, job_kill: 1 };\r
\r
  function clock(ms) {\r
    var s = Math.max(0, Math.round(ms / 1000));\r
    var m = Math.floor(s / 60);\r
    s %= 60;\r
    return m + ':' + (s < 10 ? '0' : '') + s;\r
  }\r
\r
  function span(ms) {\r
    var s = Math.round(ms / 1000);\r
    if (s < 60) return tr('seconds', {n: Math.max(1, s)});\r
    var m = Math.round(s / 60);\r
    if (m < 60) return tr('minutes', {n: m});\r
    var h = Math.floor(m / 60);\r
    return tr('hours', {n: h}) + (m % 60 ? ' ' + tr('minutes', {n: m % 60}) : '');\r
  }\r
\r
  function tokens(n) {\r
    if (n < 1000) return n + '';\r
    if (n < 1000000) return (n / 1000).toFixed(n < 10000 ? 1 : 0).replace(/\\.0$/, '') + 'k';\r
    return (n / 1000000).toFixed(1).replace(/\\.0$/, '') + 'M';\r
  }\r
\r
  function bytes(n) {\r
    if (n == null) return '';\r
    if (n < 1024) return n + ' B';\r
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0).replace(/\\.0$/, '') + ' KB';\r
    return (n / 1024 / 1024).toFixed(1).replace(/\\.0$/, '') + ' MB';\r
  }\r
\r
  function prefix(text, f) {\r
    if (f >= 1) return text;\r
    if (f <= 0 || !text) return '';\r
    var a = Array.from(text);\r
    return a.slice(0, Math.floor(a.length * f)).join('');\r
  }\r
\r
  function modelName(id) {\r
    if (!id) return null;\r
    return id.replace(/^deepseek-/i, 'DeepSeek-').replace(/-v(\\d)/i, '-V$1').replace(/-pro$/i, '-Pro').replace(/-flash$/i, '-Flash');\r
  }\r
\r
  // \u2500\u2500 The viewer \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  /**\r
   * Mounts a conversation into [host]. opts: {assets, appLink, download,\r
   * autoplay (default true)}. Returns {play, pause, seek, showAll, destroy}.\r
   */\r
  function mount(host, conv, opts) {\r
    opts = opts || {};\r
    var assets = opts.assets || {};\r
    var entries = conv.entries;\r
    var plan = timeline(entries);\r
    var duration = plan.duration;\r
\r
    // Turn index of every entry (-1 before the first turn); a turn's parts.\r
    var turnOf = [];\r
    var current = -1;\r
    entries.forEach(function (e, i) { if (e.type === 'turn') current = i; turnOf.push(current); });\r
\r
    host.textContent = '';\r
    var page = el('div', 'dv');\r
    var bar = el('header', 'dv-bar');\r
    var barInner = el('div', 'dv-bar-inner');\r
    var head = el('div', 'dv-head');\r
    var headText = el('div', 'dv-head-text');\r
    var title = el('h1', 'dv-title', conv.title);\r
    var sub = el('div', 'dv-sub');\r
    var subParts = [];\r
    var started = new Date(conv.start);\r
    subParts.push(lang === 'zh' ? tr('date', {year: started.getFullYear(), month: started.getMonth() + 1, day: started.getDate()}) : started.toLocaleDateString('en', {year: 'numeric', month: 'short', day: 'numeric'}));\r
    if (conv.model) subParts.push(modelName(conv.model));\r
    var last = 0;\r
    entries.forEach(function (e) { last = Math.max(last, e.t + (e.d || 0)); });\r
    if (last > 0) subParts.push(span(last));\r
    if (conv.range) subParts.push(tr(conv.range.to === conv.range.from ? 'turnRangeOne' : 'turnRange', {from: conv.range.from, to: conv.range.to, total: conv.range.of}));\r
    sub.textContent = subParts.join(' \xB7 ');\r
    headText.appendChild(title);\r
    headText.appendChild(sub);\r
    head.appendChild(headText);\r
    var allBtn = el('button', 'dv-pill', tr('allText'));\r
    allBtn.type = 'button';\r
    head.appendChild(allBtn);\r
    barInner.appendChild(head);\r
\r
    var transport = el('div', 'dv-transport');\r
    var playBtn = el('button', 'dv-key');\r
    playBtn.type = 'button';\r
    var seek = el('input', 'dv-seek');\r
    seek.type = 'range';\r
    seek.min = '0';\r
    seek.max = String(Math.max(1, Math.round(duration)));\r
    seek.step = '1';\r
    seek.value = '0';\r
    seek.setAttribute('aria-label', tr('progress'));\r
    var time = el('span', 'dv-time');\r
    var speedBtn = el('button', 'dv-speed', '1\xD7');\r
    speedBtn.type = 'button';\r
    speedBtn.setAttribute('aria-label', tr('speed'));\r
    transport.appendChild(playBtn);\r
    transport.appendChild(seek);\r
    transport.appendChild(time);\r
    transport.appendChild(speedBtn);\r
    barInner.appendChild(transport);\r
    bar.appendChild(barInner);\r
    page.appendChild(bar);\r
\r
    var list = el('main', 'dv-list');\r
    list.setAttribute('aria-live', 'off');\r
    page.appendChild(list);\r
\r
    var bottom = el('div', 'dv-bottom');\r
    var bottomInner = el('div', 'dv-bottom-inner');\r
    var dock = el('div', 'dv-dock');\r
    dock.hidden = true;\r
    bottomInner.appendChild(dock);\r
    var actions = el('div', 'dv-actions');\r
    if (opts.appLink) {\r
      var open = el('a', 'dv-btn dv-primary', tr('openApp'));\r
      open.href = opts.appLink;\r
      actions.appendChild(open);\r
    }\r
    if (opts.download !== false) {\r
      var dl = el('a', 'dv-btn ' + (opts.appLink ? 'dv-secondary' : 'dv-primary'), tr('download'));\r
      dl.href = opts.download || 'https://github.com/zheyuanAI/dsh-Go/releases/latest';\r
      dl.rel = 'noopener';\r
      dl.target = '_blank';\r
      actions.appendChild(dl);\r
    }\r
    if (opts.fileText) {\r
      // The file itself, for replaying (and going on) in the app.\r
      var save = el('button', 'dv-btn dv-secondary', tr('saveChat'));\r
      save.type = 'button';\r
      save.addEventListener('click', function () {\r
        var url = URL.createObjectURL(new Blob([opts.fileText], { type: 'application/vnd.dshgo+json' }));\r
        var a = el('a');\r
        a.href = url;\r
        a.download = fileName(conv.title);\r
        document.body.appendChild(a);\r
        a.click();\r
        a.remove();\r
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);\r
      });\r
      actions.appendChild(save);\r
    }\r
    if (actions.childNodes.length) bottomInner.appendChild(actions);\r
    bottom.appendChild(bottomInner);\r
    page.appendChild(bottom);\r
    host.appendChild(page);\r
\r
    // \u2500\u2500 State \u2500\u2500\r
    var now = 0;\r
    var speed = 1;\r
    var playing = false;\r
    var raf = 0;\r
    var lastTick = 0;\r
    var follow = true;\r
    var rows = {};       // key \u2192 {el, sig}\r
    var openKeys = {};   // keys the reader opened\r
    var closedKeys = {}; // keys the reader closed (live groups)\r
    var todoOpen = false;\r
    var animate = false;\r
\r
    function setPlayIcon() {\r
      playBtn.textContent = '';\r
      var ended = now >= duration && !playing;\r
      playBtn.appendChild(icon(playing ? 'pause' : ended ? 'replay' : 'play'));\r
      playBtn.setAttribute('aria-label', playing ? tr('pause') : ended ? tr('replay') : tr('play'));\r
    }\r
\r
    function setClock() {\r
      seek.value = String(Math.round(now));\r
      seek.style.setProperty('--dv-p', (duration ? now / duration * 100 : 100) + '%');\r
      time.textContent = clock(now) + ' / ' + clock(duration);\r
    }\r
\r
    function turnClosed(ti) {\r
      var end = plan.turnEnds[ti];\r
      return end != null && now >= end;\r
    }\r
\r
    // \u2500\u2500 Rows \u2500\u2500\r
    function bubbleRow(e) {\r
      var row = el('div', 'dv-row dv-user');\r
      if (e.source && e.source !== 'user') row.appendChild(el('div', 'dv-source', e.source === 'goal' ? tr('goalResume') : e.source === 'schedule' ? tr('schedule') : tr('auto')));\r
      if (e.images.length) {\r
        var shots = el('div', 'dv-shots');\r
        var one = e.images.length === 1;\r
        e.images.forEach(function (img) {\r
          var url = assets[img.id];\r
          if (!url) { shots.appendChild(el('div', 'dv-shot dv-missing', tr('image'))); return; }\r
          var b = el('button', 'dv-shot ' + (one ? 'dv-one' : 'dv-many'));\r
          b.type = 'button';\r
          b.setAttribute('aria-label', img.name || tr('image'));\r
          var im = el('img');\r
          im.alt = img.name || tr('image');\r
          im.src = url;\r
          if (img.w && img.h) { im.width = img.w; im.height = img.h; }\r
          b.appendChild(im);\r
          b.addEventListener('click', function () { lightbox(url); });\r
          shots.appendChild(b);\r
        });\r
        row.appendChild(shots);\r
      }\r
      e.files.forEach(function (f) {\r
        var chip = el('div', 'dv-file');\r
        chip.appendChild(icon('file', 'dv-chev'));\r
        chip.appendChild(el('span', null, f.name));\r
        if (f.size != null) chip.appendChild(el('span', null, bytes(f.size)));\r
        row.appendChild(chip);\r
      });\r
      if (e.text.trim()) row.appendChild(el('div', 'dv-bubble', e.text));\r
      return row;\r
    }\r
\r
    function thinkRow(key, text, active, ms) {\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      var g = el('span', 'dv-glyph');\r
      g.style.background = 'var(--dv-t3)';\r
      g.style.color = 'var(--dv-o3)';\r
      g.appendChild(icon('think'));\r
      ln.appendChild(g);\r
      ln.appendChild(el('span', 'dv-label', active ? tr('thinkingActive') : tr('thinking')));\r
      ln.appendChild(el('span', 'dv-detail', text.replace(/\\s+/g, ' ').slice(0, 160)));\r
      if (active) ln.appendChild(el('span', 'dv-spin'));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      body.appendChild(el('div', 'dv-think', text));\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    function replyRow(e, text, streaming, done, foot) {\r
      var row = el('div', 'dv-row');\r
      var md = el('div', 'dv-md');\r
      markdown(streaming ? repairStream(text) : text, md);\r
      if (streaming) caret(md);\r
      row.appendChild(md);\r
      if (done && e.cut) row.appendChild(el('div', 'dv-cut', tr('interrupted')));\r
      if (foot) row.appendChild(el('div', 'dv-foot-note', foot));\r
      return row;\r
    }\r
\r
    function toolRow(key, e, running) {\r
      var bad = !running && (e.status === 'failed' || e.status === 'denied');\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      var tone = TONES[e.name] != null ? TONES[e.name] : 7;\r
      var g = el('span', 'dv-glyph');\r
      g.style.background = 'var(--dv-t' + tone + ')';\r
      g.style.color = 'var(--dv-o' + tone + ')';\r
      g.appendChild(icon(e.name.indexOf('mcp__') === 0 ? 'tool' : TONE_ICON[tone]));\r
      ln.appendChild(g);\r
      ln.appendChild(el('span', 'dv-label', e.verb || e.name));\r
      ln.appendChild(el('span', 'dv-detail' + (CODE_TOOLS[e.name] ? ' dv-mono' : ''), e.summary));\r
      if (running) ln.appendChild(el('span', 'dv-spin'));\r
      else if (bad) ln.appendChild(el('span', 'dv-state dv-bad', e.status === 'denied' ? tr('declined') : tr('failed')));\r
      else if (e.status === 'cancelled') ln.appendChild(el('span', 'dv-state', tr('cancelled')));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      var cmd = typeof e.args.command === 'string' ? e.args.command : null;\r
      if (cmd) body.appendChild(el('div', 'dv-out', '$ ' + cmd));\r
      else {\r
        var keys = Object.keys(e.args);\r
        if (keys.length) {\r
          var shown = {};\r
          keys.slice(0, 12).forEach(function (k) { shown[k] = e.args[k]; });\r
          var argText;\r
          try { argText = JSON.stringify(shown, null, 2); } catch (x) { argText = ''; }\r
          if (argText) body.appendChild(el('div', 'dv-out', argText));\r
        }\r
      }\r
      if (!running) {\r
        if (e.error) body.appendChild(el('div', 'dv-out', e.error));\r
        if (e.result) {\r
          body.appendChild(el('div', 'dv-out-label', e.more ? tr('outputCut') : tr('output')));\r
          body.appendChild(el('div', 'dv-out', e.result));\r
        }\r
      }\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    function toggle(ln, row, body, key) {\r
      function flip() {\r
        var open = body.hidden;\r
        body.hidden = !open;\r
        row.classList.toggle('dv-open', open);\r
        if (open) { openKeys[key] = 1; delete closedKeys[key]; } else { delete openKeys[key]; closedKeys[key] = 1; }\r
      }\r
      ln.addEventListener('click', flip);\r
      ln.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); flip(); } });\r
    }\r
\r
    function noticeRow(e) {\r
      var bad = e.kind === 'error' || e.kind === 'blocked';\r
      var row = el('div', 'dv-row dv-proc');\r
      var n = el('div', 'dv-notice' + (bad ? ' dv-bad' : ''));\r
      n.appendChild(icon('warn', 'dv-chev'));\r
      n.appendChild(el('span', null, e.text || (e.kind === 'aborted' ? tr('stopped') : tr('error'))));\r
      row.appendChild(n);\r
      return row;\r
    }\r
\r
    function commandRow(e) {\r
      var row = el('div', 'dv-row dv-proc');\r
      var c = el('div', 'dv-cmd', e.line);\r
      if (e.text) c.appendChild(el('span', null, '  ' + e.text.split('\\n')[0].slice(0, 200)));\r
      row.appendChild(c);\r
      return row;\r
    }\r
\r
    function footnote(turn) {\r
      var parts = [];\r
      if (turn.d != null) parts.push(span(turn.d));\r
      if (turn.steps) parts.push(tr('steps', {n: turn.steps}));\r
      if (turn.tokens) parts.push(tr('tokenCount', {n: turn.tokens, count: tokens(turn.tokens)}));\r
      return parts.join(' \xB7 ');\r
    }\r
\r
    function foldRow(key, tools, messages, thoughts, children) {\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      ln.appendChild(icon('check', 'dv-fold-ok'));\r
      var label = [tr('completed')];\r
      if (tools) label.push(tr('toolCalls', {n: tools}));\r
      if (messages) label.push(tr('messages', {n: messages}));\r
      if (!tools && !messages && thoughts) label.push(tr('thoughts', {n: thoughts}));\r
      ln.appendChild(el('span', 'dv-label', label.join(' \xB7 ')));\r
      ln.appendChild(el('span', 'dv-detail', ''));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      children.forEach(function (c) { c.classList.add('dv-quiet'); body.appendChild(c); });\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    // What the list shows at \`now\`: [{key, sig, build}].\r
    function model() {\r
      var out = [];\r
      var n = 0;\r
      while (n < plan.beats.length && plan.beats[n].start <= now) n++;\r
      var i = 0;\r
      while (i < n) {\r
        var e = entries[i];\r
        if (e.type === 'turn') {\r
          // The turn's parts up to the next turn (or what has appeared).\r
          var j = i + 1;\r
          while (j < n && entries[j].type !== 'turn') j++;\r
          var closed = turnClosed(i) && e.end === 'completed';\r
          if (closed) foldTurn(out, i, j); else liveRange(out, i + 1, j);\r
          if (turnClosed(i) && !closed) {\r
            var foot = footnote(e);\r
            if (foot) out.push(footPart(i, foot));\r
          }\r
          i = j;\r
        } else {\r
          var k = i + 1;\r
          while (k < n && entries[k].type !== 'turn') k++;\r
          liveRange(out, i, k);\r
          i = k;\r
        }\r
      }\r
      return out;\r
    }\r
\r
    function partOf(i) {\r
      var e = entries[i];\r
      var b = plan.beats[i];\r
      var done = now >= b.end;\r
      switch (e.type) {\r
        case 'user': return { key: 'u' + i, sig: '1', build: function () { return bubbleRow(e); } };\r
        case 'reply': {\r
          var parts = [];\r
          if (e.think) {\r
            var tActive = now < b.think;\r
            var tText = tActive ? prefix(e.think, (now - b.start) / Math.max(1, b.think - b.start)) : e.think;\r
            parts.push({ key: 'k' + i, sig: (tActive ? 'a' : 'd') + tText.length + (openKeys['k' + i] ? 'o' : ''), build: function () { return thinkRow('k' + i, tText, tActive, b.think - b.start); } });\r
          }\r
          var body = e.plain || e.text;\r
          if (body.trim() || (done && e.cut)) {\r
            var shown = done ? body : now < b.think ? '' : prefix(body, (now - b.think) / Math.max(1, b.end - b.think));\r
            if (shown || done) parts.push({ key: 'r' + i, sig: (done ? 'd' : 's') + shown.length, build: function () { return replyRow(e, shown, !done, done, null); } });\r
          }\r
          return parts;\r
        }\r
        case 'tool': return { key: 't' + i, sig: (done ? 'd' : 'r') + (openKeys['t' + i] ? 'o' : ''), build: function () { return toolRow('t' + i, e, !done); } };\r
        case 'notice': return { key: 'n' + i, sig: '1', build: function () { return noticeRow(e); } };\r
        case 'command': return { key: 'c' + i, sig: '1', build: function () { return commandRow(e); } };\r
        default: return null;\r
      }\r
    }\r
\r
    function liveRange(out, from, to) {\r
      for (var i = from; i < to; i++) {\r
        var p = partOf(i);\r
        if (!p) continue;\r
        if (Array.isArray(p)) p.forEach(function (x) { out.push(x); }); else out.push(p);\r
      }\r
    }\r
\r
    function foldTurn(out, ti, to) {\r
      // As the app's list: a turn folds only when it is one prompt's whole\r
      // turn (a message sent while it ran keeps it open).\r
      var prompts = 0;\r
      for (var u = ti + 1; u < to; u++) if (entries[u].type === 'user') prompts++;\r
      var foot = footnote(entries[ti]);\r
      if (prompts > 1) {\r
        liveRange(out, ti + 1, to);\r
        if (foot) out.push(footPart(ti, foot));\r
        return;\r
      }\r
      var first = ti + 1;\r
      if (first < to && entries[first].type === 'user') { out.push(partOf(first)); first++; }\r
      // The answer: the last reply with text, when no work follows it.\r
      var answer = -1;\r
      for (var i = to - 1; i >= first; i--) {\r
        var e = entries[i];\r
        if (e.type === 'reply' && (e.plain || e.text).trim()) { answer = i; break; }\r
        if (e.type === 'tool' || e.type === 'reply') break;\r
      }\r
      var processEnd = answer < 0 ? to : answer;\r
      var procParts = [];\r
      var kept = [];\r
      var tools = 0, messages = 0, thoughts = 0;\r
      for (var k = first; k < processEnd; k++) {\r
        var en = entries[k];\r
        if (en.type === 'user' || en.type === 'command') { kept.push(k); continue; }\r
        if (en.type === 'tool') tools++;\r
        if (en.type === 'reply') { if ((en.plain || en.text).trim()) messages++; if (en.think) thoughts++; }\r
        var p = partOf(k);\r
        if (!p) continue;\r
        if (Array.isArray(p)) p.forEach(function (x) { procParts.push(x); }); else procParts.push(p);\r
      }\r
      var answerThink = answer >= 0 && !!entries[answer].think;\r
      if (answerThink) thoughts++;\r
      var keptParts = kept.map(function (k) { return partOf(k); }).filter(Boolean);\r
      if (tools === 0 && messages === 0 && procParts.length + (answerThink ? 1 : 0) <= 1) {\r
        // A plain answer: its thinking pill is one line already.\r
        procParts.forEach(function (x) { out.push(x); });\r
        keptParts.forEach(function (x) { out.push(x); });\r
        if (answer >= 0) {\r
          if (answerThink) out.push(thinkPart(answer));\r
          out.push(answerPart(answer, foot));\r
        } else if (foot) out.push(footPart(ti, foot));\r
        return;\r
      }\r
      if (answerThink) procParts.push(thinkPart(answer));\r
      var key = 'f' + ti;\r
      var sig = 'f' + procParts.length + (openKeys[key] ? 'o' : '') + procParts.map(function (p) { return p.key + p.sig; }).join(',');\r
      out.push({\r
        key: key, sig: sig, build: function () {\r
          return foldRow(key, tools, messages, thoughts, procParts.map(function (p) { return p.build(); }));\r
        }\r
      });\r
      keptParts.forEach(function (x) { out.push(x); });\r
      if (answer >= 0) out.push(answerPart(answer, foot));\r
      else if (foot) out.push(footPart(ti, foot));\r
    }\r
\r
    function thinkPart(i) {\r
      var e = entries[i];\r
      return { key: 'k' + i, sig: 'd' + (openKeys['k' + i] ? 'o' : ''), build: function () { return thinkRow('k' + i, e.think, false, 0); } };\r
    }\r
\r
    function footPart(ti, foot) {\r
      return { key: 'ft' + ti, sig: foot, build: function () { var r = el('div', 'dv-row'); r.appendChild(el('div', 'dv-foot-note', foot)); return r; } };\r
    }\r
\r
    function answerPart(i, foot) {\r
      var e = entries[i];\r
      return { key: 'r' + i, sig: 'a' + (foot || ''), build: function () { return replyRow(e, e.plain || e.text, false, true, foot); } };\r
    }\r
\r
    // \u2500\u2500 Dock \u2500\u2500\r
    function renderDock() {\r
      var todos = null, goal = null, running = false;\r
      var n = 0;\r
      while (n < plan.beats.length && plan.beats[n].start <= now) {\r
        var e = entries[n];\r
        if (e.type === 'turn') { todos = null; if (!turnClosed(n)) running = true; }\r
        else if (e.type === 'todos') todos = e.items;\r
        else if (e.type === 'goal') goal = e.text ? e : null;\r
        n++;\r
      }\r
      var sig = JSON.stringify([todos, goal && goal.text, goal && goal.phase, running, todoOpen]);\r
      if (dock.dataset.sig === sig) return;\r
      dock.dataset.sig = sig;\r
      dock.textContent = '';\r
      dock.hidden = !(todos && todos.length) && !goal;\r
      if (todos && todos.length) {\r
        var done = todos.filter(function (t) { return t.status === 'completed'; }).length;\r
        var cur = todos.filter(function (t) { return t.status === 'in_progress'; })[0] || todos.filter(function (t) { return t.status !== 'completed'; })[0];\r
        var row = el('div', 'dv-dock-row');\r
        row.setAttribute('role', 'button');\r
        row.tabIndex = 0;\r
        var g = el('span', 'dv-glyph');\r
        g.style.background = 'var(--dv-t6)';\r
        g.style.color = 'var(--dv-o6)';\r
        g.appendChild(icon('plan'));\r
        row.appendChild(g);\r
        row.appendChild(el('b', null, done + '/' + todos.length));\r
        row.appendChild(el('span', 'dv-detail', done === todos.length ? tr('allDone') : ((running && cur.status === 'in_progress') ? tr('now') : tr('next')) + cur.text));\r
        row.appendChild(icon('chevron', 'dv-chev'));\r
        row.addEventListener('click', function () { todoOpen = !todoOpen; renderDock(); });\r
        dock.appendChild(row);\r
        if (todoOpen) {\r
          var ul = el('ul', 'dv-todos');\r
          todos.forEach(function (t) {\r
            ul.appendChild(el('li', t.status === 'completed' ? 'dv-done' : t.status === 'in_progress' ? 'dv-now' : null, t.text));\r
          });\r
          dock.appendChild(ul);\r
        }\r
      }\r
      if (goal) {\r
        var gr = el('div', 'dv-dock-row');\r
        var gg = el('span', 'dv-glyph');\r
        gg.style.background = 'var(--dv-t5)';\r
        gg.style.color = 'var(--dv-o5)';\r
        gg.appendChild(icon('flag'));\r
        gr.appendChild(gg);\r
        gr.appendChild(el('b', null, tr('goal')));\r
        gr.appendChild(el('span', 'dv-detail', goal.text.replace(/\\s+/g, ' ')));\r
        var phase = { paused: tr('paused'), blocked: tr('blocked'), complete: tr('achieved') }[goal.phase];\r
        if (phase) gr.appendChild(el('span', 'dv-state' + (goal.phase === 'blocked' ? ' dv-bad' : ''), phase));\r
        dock.appendChild(gr);\r
      }\r
    }\r
\r
    function render() {\r
      var want = model();\r
      var keep = {};\r
      var prev = null;\r
      want.forEach(function (w) {\r
        keep[w.key] = 1;\r
        var have = rows[w.key];\r
        if (!have || have.sig !== w.sig) {\r
          var node = w.build();\r
          if (!animate || have) node.classList.add('dv-quiet');\r
          if (have) list.replaceChild(node, have.el);\r
          rows[w.key] = have = { el: node, sig: w.sig };\r
        }\r
        var next = prev ? prev.nextSibling : list.firstChild;\r
        if (next !== have.el) list.insertBefore(have.el, next);\r
        prev = have.el;\r
      });\r
      Object.keys(rows).forEach(function (k) {\r
        if (!keep[k]) { if (rows[k].el.parentNode) rows[k].el.parentNode.removeChild(rows[k].el); delete rows[k]; }\r
      });\r
      renderDock();\r
      setClock();\r
      if (follow) window.scrollTo(0, document.documentElement.scrollHeight);\r
    }\r
\r
    function tick(ts) {\r
      raf = 0;\r
      if (!playing) return;\r
      var dt = lastTick ? Math.min(250, ts - lastTick) : 16;\r
      lastTick = ts;\r
      now = Math.min(duration, now + dt * speed);\r
      animate = true;\r
      render();\r
      if (now >= duration) { playing = false; setPlayIcon(); return; }\r
      raf = requestAnimationFrame(tick);\r
    }\r
\r
    function play() {\r
      if (now >= duration) { now = 0; follow = true; window.scrollTo(0, 0); }\r
      playing = true;\r
      lastTick = 0;\r
      setPlayIcon();\r
      if (!raf) raf = requestAnimationFrame(tick);\r
    }\r
\r
    function pause() {\r
      playing = false;\r
      if (raf) cancelAnimationFrame(raf);\r
      raf = 0;\r
      setPlayIcon();\r
    }\r
\r
    function seekTo(ms) {\r
      now = clamp(ms, 0, duration);\r
      animate = false;\r
      render();\r
      setPlayIcon();\r
    }\r
\r
    function showAll() {\r
      pause();\r
      follow = false;\r
      seekTo(duration);\r
      setPlayIcon();\r
    }\r
\r
    playBtn.addEventListener('click', function () { if (playing) pause(); else play(); });\r
    speedBtn.addEventListener('click', function () {\r
      speed = speed === 1 ? 2 : speed === 2 ? 4 : 1;\r
      speedBtn.textContent = speed + '\xD7';\r
    });\r
    seek.addEventListener('input', function () { follow = true; seekTo(Number(seek.value)); });\r
    allBtn.addEventListener('click', function () { showAll(); window.scrollTo(0, 0); });\r
    window.addEventListener('scroll', function () {\r
      var gapPx = document.documentElement.scrollHeight - (window.scrollY + window.innerHeight);\r
      follow = gapPx < 80;\r
    }, { passive: true });\r
    function onKey(ev) {\r
      if (ev.target && /INPUT|TEXTAREA|BUTTON|A/.test(ev.target.tagName)) return;\r
      if (ev.key === ' ') { ev.preventDefault(); if (playing) pause(); else play(); }\r
    }\r
    document.addEventListener('keydown', onKey);\r
\r
    setPlayIcon();\r
    render();\r
    if (opts.autoplay !== false && duration > 0) setTimeout(play, 500);\r
    else if (duration <= 0) showAll();\r
\r
    return {\r
      play: play, pause: pause, seek: seekTo, showAll: showAll,\r
      get time() { return now; }, get duration() { return duration; },\r
      destroy: function () { pause(); document.removeEventListener('keydown', onKey); host.textContent = ''; }\r
    };\r
  }\r
\r
  function lightbox(url) {\r
    var box = el('div', 'dv-lightbox');\r
    var im = el('img');\r
    im.src = url;\r
    im.alt = '';\r
    box.appendChild(im);\r
    box.addEventListener('click', function () { box.remove(); });\r
    document.addEventListener('keydown', function esc(ev) { if (ev.key === 'Escape') { box.remove(); document.removeEventListener('keydown', esc); } });\r
    (document.querySelector('.dv') || document.body).appendChild(box);\r
  }\r
\r
\r
  function fileName(title) {\r
    var base = String(title || tr('chat')).replace(/[\\\\/:*?"<>|\\u0000-\\u001f]+/g, ' ').trim().slice(0, 40) || tr('chat');\r
    return base + '.dshgo';\r
  }\r
\r
  function card(host, heading, text, button) {\r
    host.textContent = '';\r
    var page = el('div', 'dv');\r
    var c = el('section', 'dv-open-card');\r
    c.appendChild(el('h1', null, heading));\r
    if (text) c.appendChild(el('p', null, text));\r
    if (button) c.appendChild(button);\r
    page.appendChild(c);\r
    host.appendChild(page);\r
    return c;\r
  }\r
\r
  /** \u300C\u67E5\u770B\u5BF9\u8BDD\u300D: pick a \`.dshgo\` file or drop one anywhere on the page. */\r
  function opener(host, opts) {\r
    opts = opts || {};\r
    var input = el('input');\r
    input.type = 'file';\r
    input.accept = '.dshgo,application/vnd.dshgo+json,application/json';\r
    input.hidden = true;\r
    var pick = el('button', 'dv-btn dv-primary', tr('pickFile'));\r
    pick.type = 'button';\r
    pick.addEventListener('click', function () { input.click(); });\r
    var c = card(host, tr('viewChat'), tr('pickHint'), pick);\r
    c.appendChild(input);\r
    var error = el('p', 'dv-error');\r
    error.hidden = true;\r
    c.appendChild(error);\r
    async function take(file) {\r
      if (!file) return;\r
      if (file.size > 32 * 1024 * 1024) { error.textContent = tr('fileTooLarge'); error.hidden = false; return; }\r
      try {\r
        var text = await file.text();\r
        var opened = await openFile(text);\r
        mount(host, opened.conversation, { assets: opened.assets, fileText: text, download: opts.download });\r
        document.title = opened.conversation.title + ' \xB7 dsh-go';\r
        detachDrop();\r
      } catch (e) {\r
        error.textContent = errorText(e);\r
        error.hidden = false;\r
      }\r
    }\r
    input.addEventListener('change', function () { take(input.files && input.files[0]); });\r
    var shade = null;\r
    var depth = 0;\r
    function enter(ev) { ev.preventDefault(); depth++; if (!shade) { shade = el('div', 'dv-drop', tr('drop')); host.firstChild.appendChild(shade); } }\r
    function over(ev) { ev.preventDefault(); }\r
    function leave() { depth = Math.max(0, depth - 1); if (!depth && shade) { shade.remove(); shade = null; } }\r
    function drop(ev) {\r
      ev.preventDefault();\r
      depth = 0;\r
      if (shade) { shade.remove(); shade = null; }\r
      take(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]);\r
    }\r
    function detachDrop() {\r
      document.removeEventListener('dragenter', enter);\r
      document.removeEventListener('dragover', over);\r
      document.removeEventListener('dragleave', leave);\r
      document.removeEventListener('drop', drop);\r
    }\r
    document.addEventListener('dragenter', enter);\r
    document.addEventListener('dragover', over);\r
    document.addEventListener('dragleave', leave);\r
    document.addEventListener('drop', drop);\r
  }\r
\r
  /** Starts whichever page this is: the file inside it (the exported page),\r
   *  a hosted link, or the file opener. */\r
  async function boot(host) {\r
    host = host || document.getElementById('dv-root');\r
    var data = document.getElementById('dshgo-data');\r
    var embedded = data ? data.textContent.trim() : '';\r
    try {\r
      // The exported page has the file here; the template's own marker is\r
      // split so filling it in can't touch this line.\r
      if (embedded && embedded !== '__DSHGO_' + 'DATA__') {\r
        var opened = await openFile(embedded, { trust: true });\r
        mount(host, opened.conversation, { assets: opened.assets, fileText: embedded });\r
        return;\r
      }\r
      var path = /\\/c\\/([A-Za-z0-9]{6,32})\\/?$/.exec(location.pathname);\r
      if (path) {\r
        document.title = tr('viewerTitle');\r
        var key = new URLSearchParams(location.hash.replace(/^#/, '')).get('k');\r
        if (!key) throw new Error('key');\r
        card(host, tr('opening'), null, null);\r
        var hosted = await openHosted(path[1], key);\r
        document.title = hosted.conversation.title + ' \xB7 dsh-go';\r
        mount(host, hosted.conversation, {\r
          assets: hosted.assets,\r
          fileText: hosted.fileText,\r
          // The app opens the same link (the key stays in the fragment).\r
          appLink: 'dshgo://' + location.host + location.pathname + location.hash\r
        });\r
        return;\r
      }\r
      document.title = tr('viewerTitle');\r
      opener(host);\r
    } catch (e) {\r
      var dl = el('a', 'dv-btn dv-secondary', tr('download'));\r
      dl.href = 'https://github.com/zheyuanAI/dsh-Go/releases/latest';\r
      dl.rel = 'noopener';\r
      card(host, errorText(e), null, dl);\r
    }\r
  }\r
\r
  /** An error's short text. */\r
  function errorText(e) {\r
    var m = String(e && e.message);\r
    return m === 'newer' ? tr('errorNewer')\r
      : m === 'browser' ? tr('errorBrowser')\r
      : m === 'kind' ? tr('errorKind')\r
      : m === 'gone' ? tr('errorGone')\r
      : m === 'network' ? tr('errorNetwork')\r
      : m === 'key' ? tr('errorKey')\r
      : tr('errorFormat');\r
  }\r
\r
  root.DshgoViewer = {\r
    decodeCode: decodeCode,\r
    readEnvelope: readEnvelope,\r
    readConversation: readConversation,\r
    readAssets: readAssets,\r
    openFile: openFile,\r
    decryptHosted: decryptHosted,\r
    openHosted: openHosted,\r
    opener: opener,\r
    boot: boot,\r
    timeline: timeline,\r
    mount: mount,\r
    markdown: markdown,\r
    errorText: errorText,\r
    PACE: PACE\r
  };\r
})(typeof window !== 'undefined' ? window : globalThis);\r
DshgoViewer.boot();\r
<\/script>\r
<footer><a href="https://github.com/zheyuanAI/dsh-Go/tree/local/services/share-worker">\u6E90\u7801 \xB7 AGPL-3.0</a></footer></body>\r
</html>\r
`, "type": "text/html; charset=utf-8" }, "/share/": { "body": `<!doctype html>\r
<html lang="zh-CN">\r
<head>\r
<meta charset="utf-8">\r
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\r
<meta name="referrer" content="no-referrer">\r
<meta name="robots" content="noindex">\r
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src https://api.github.com https://gist.githubusercontent.com; base-uri 'none'; form-action 'none'">\r
<meta name="color-scheme" content="light dark">\r
<title>dsh-go \u5206\u4EAB</title>\r
<link rel="icon" href="favicon.svg" type="image/svg+xml">\r
<link rel="apple-touch-icon" href="apple-touch-icon.png">\r
<link rel="stylesheet" href="viewer.css">\r
<style>\r
  :root {\r
    --bg: #eef0f5;\r
    --card: #ffffff;\r
    --ink: #161a22;\r
    --ink-2: #4a5160;\r
    --ink-3: #8a90a0;\r
    --line: rgba(20, 24, 34, 0.08);\r
    --primary: #4d6bfe;\r
    --on-primary: #ffffff;\r
    --tile: rgba(77, 107, 254, 0.12);\r
    --ok: #2f7d4f;\r
    --ok-bg: rgba(47, 125, 79, 0.12);\r
    --danger: #c0392b;\r
    /* The brand glyph's gradient stops, for light pages (app/assets/brand/glyph-light.svg). */\r
    --g-tail-0: #4261cd; --g-tail-1: #5e93e1; --g-fin-0: #4e68ce; --g-fin-1: #6692db; --g-belly-0: #839ae6; --g-belly-1: #7b8de0; --g-belly-2: #7075d2; --g-bubble-0: #779ee6; --g-bubble-1: #6f91e0; --g-bubble-2: #7075d2;\r
  }\r
  @media (prefers-color-scheme: dark) {\r
    :root {\r
      --bg: #12151c;\r
      --card: #1d212b;\r
      --ink: #eef0f5;\r
      --ink-2: #b6bccb;\r
      --ink-3: #7c8396;\r
      --line: rgba(255, 255, 255, 0.08);\r
      --primary: #8ea2ff;\r
      --on-primary: #10131a;\r
      --tile: rgba(142, 162, 255, 0.16);\r
      --ok: #8fd3a8;\r
      --ok-bg: rgba(143, 211, 168, 0.14);\r
      --danger: #ff8a7a;\r
      /* \u2026and for dark pages (glyph-dark.svg). */\r
      --g-tail-0: #8faffa; --g-tail-1: #ddeefd; --g-fin-0: #8eadfb; --g-fin-1: #cde2fb; --g-belly-0: #bfccfa; --g-belly-1: #ccd8fb; --g-belly-2: #eceafe; --g-bubble-0: #a6c3fa; --g-bubble-1: #b7ccfa; --g-bubble-2: #ece5fc;\r
    }\r
  }\r
  * { box-sizing: border-box; }\r
  html, body { margin: 0; background: var(--bg); color: var(--ink); }\r
  body {\r
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;\r
    min-height: 100vh;\r
    display: flex;\r
    justify-content: center;\r
    padding: max(32px, env(safe-area-inset-top)) 16px max(32px, env(safe-area-inset-bottom));\r
  }\r
  main { width: 100%; max-width: 440px; }\r
  .brand { display: flex; align-items: center; gap: 8px; color: var(--ink-3); font-size: 13px; margin: 0 4px 16px; }\r
  .brand b { color: var(--ink); font-weight: 600; letter-spacing: 0.01em; }\r
  /* Lockup (BrandLockup in the app): glyph 1.25\xD7 the word's size, 0.36\xD7 from it, its visual\r
     centre (57% down its box) on the word's x-height centre. */\r
  .lockup { white-space: nowrap; }\r
  .lockup .glyph { width: 1.3105em; height: 1.25em; margin-right: 0.36em; vertical-align: -0.27em; }\r
  .card { background: var(--card); border-radius: 28px; padding: 24px 20px 20px; box-shadow: 0 8px 28px rgba(0, 0, 0, 0.06); border: 0.5px solid var(--line); }\r
  .hero { display: flex; align-items: center; gap: 16px; }\r
  .tile { flex: none; width: 56px; height: 56px; border-radius: 14px; background: var(--tile); color: var(--primary); display: grid; place-items: center; font-size: 24px; font-weight: 600; }\r
  .tile svg { width: 26px; height: 26px; }\r
  h1 { font-size: 21px; line-height: 1.3; margin: 0; font-weight: 600; overflow-wrap: anywhere; }\r
  .sub { color: var(--ink-3); font-size: 13px; margin-top: 2px; overflow-wrap: anywhere; }\r
  .summary { color: var(--ink-2); margin: 16px 0 0; overflow-wrap: anywhere; }\r
  .facts { margin: 16px 0 0; padding: 0; list-style: none; border-top: 0.5px solid var(--line); }\r
  .facts li { display: flex; justify-content: space-between; gap: 16px; padding: 12px 0; border-bottom: 0.5px solid var(--line); }\r
  .facts li span:first-child { color: var(--ink-2); flex: none; }\r
  .facts li span:last-child { text-align: right; color: var(--ink); overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }\r
  .group { margin-top: 18px; }\r
  .group h2 { font-size: 13px; font-weight: 600; color: var(--ink-3); margin: 0 0 6px; }\r
  .group ul { margin: 0; padding: 0; list-style: none; }\r
  .group li { display: flex; justify-content: space-between; gap: 16px; padding: 6px 0; }\r
  .group li span:last-child { color: var(--ink-3); text-align: right; }\r
  .mono { font-family: ui-monospace, "JetBrains Mono", Menlo, monospace; font-size: 13px; }\r
  .chip { display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px; border-radius: 999px; background: var(--ok-bg); color: var(--ok); font-size: 13px; font-weight: 600; }\r
  .chip::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }\r
  .actions { display: grid; gap: 12px; margin-top: 24px; }\r
  .btn { display: flex; align-items: center; justify-content: center; height: 48px; border-radius: 999px; font-size: 16px; font-weight: 600; text-decoration: none; }\r
  .btn.primary { background: var(--primary); color: var(--on-primary); }\r
  .btn.secondary { color: var(--ink); border: 1px solid var(--line); background: transparent; }\r
  .note { color: var(--ink-3); font-size: 13px; text-align: center; margin: 14px 0 0; }\r
  .error { color: var(--danger); }\r
  [hidden] { display: none !important; }\r
  /* A conversation (viewer.css) takes the whole page. */\r
  body.dv-page { display: block; padding: 0; }\r
</style>\r
</head>\r
<body>\r
<main>\r
  <div class="brand"><span class="lockup"><svg class="glyph" viewBox="26.75 28.01 54.51 52" aria-hidden="true"><defs><linearGradient id="m-tail" gradientUnits="userSpaceOnUse" x1="36.3" y1="57" x2="66.5" y2="40"><stop offset="0" style="stop-color:var(--g-tail-0)"/><stop offset="1" style="stop-color:var(--g-tail-1)"/></linearGradient><linearGradient id="m-fin" gradientUnits="userSpaceOnUse" x1="40.2" y1="41.5" x2="28.1" y2="39.4"><stop offset="0" style="stop-color:var(--g-fin-0)"/><stop offset="1" style="stop-color:var(--g-fin-1)"/></linearGradient><radialGradient id="m-belly" gradientUnits="userSpaceOnUse" cx="0" cy="0" r="1" gradientTransform="matrix(27 0 0 13.5 52.7 71)"><stop offset="0" style="stop-color:var(--g-belly-0)"/><stop offset="0.6" style="stop-color:var(--g-belly-1)"/><stop offset="1" style="stop-color:var(--g-belly-2)"/></radialGradient><radialGradient id="m-bubble" gradientUnits="userSpaceOnUse" cx="74.773" cy="47.737" r="11.858"><stop offset="0" style="stop-color:var(--g-bubble-0)"/><stop offset="0.55" style="stop-color:var(--g-bubble-1)"/><stop offset="1" style="stop-color:var(--g-bubble-2)"/></radialGradient></defs><path fill="url(#m-tail)" d="M41.533 42.237C44.542 35.225 52.318 30.559 59.471 28.765C60.371 28.538 62.707 28.015 63.555 28.015C64.422 28.015 64.421 28.514 64.421 29.29C64.421 31.68 63.303 34.553 62.143 36.621C55.998 47.579 48.019 44.056 43.838 46.999C43.15 47.483 42.766 48.054 42.766 48.912C42.766 50.39 43.965 52.011 44.897 53.082C45.928 54.267 47.16 55.238 48.469 56.094C55.176 60.483 63.472 60.609 71.206 61.347C74.082 61.621 79.534 62.636 79.534 66.422C79.534 68.215 78.222 70.141 77.075 71.438C71.344 77.92 61.895 80.004 53.58 80.004C44.713 80.004 35.314 77.576 31.142 68.924C30.012 66.582 29.365 64.181 29.365 61.571C29.365 55.356 33.535 50.83 37.86 46.956C38.345 46.522 38.831 46.123 39.305 45.676C38.855 45.728 38.235 45.778 37.786 45.778C33.274 45.778 29.511 43.364 27.53 39.337C27.273 38.812 26.75 37.645 26.75 37.084C26.75 36.858 26.762 36.709 26.938 36.537C27.598 35.893 30.489 35.739 31.449 35.739C34.863 35.739 39.247 36.73 40.913 40.064C41.275 40.789 41.476 41.422 41.533 42.237Z"/><path fill="url(#m-fin)" d="M39.305 45.676C38.855 45.728 38.235 45.778 37.786 45.778C33.274 45.778 29.511 43.364 27.53 39.337C27.273 38.812 26.75 37.645 26.75 37.084C26.75 36.858 26.762 36.709 26.938 36.537C27.598 35.893 30.489 35.739 31.449 35.739C34.863 35.739 39.247 36.73 40.913 40.064C41.275 40.789 41.476 41.422 41.533 42.237C40.939 43.623 40.431 44.616 39.305 45.676Z"/><path fill="url(#m-belly)" d="M71.206 61.347C74.082 61.621 79.534 62.636 79.534 66.422C79.534 68.215 78.222 70.141 77.075 71.438C71.344 77.92 61.895 80.004 53.58 80.004C44.713 80.004 35.314 77.576 31.142 68.924C30.012 66.582 29.365 64.181 29.365 61.571C29.365 55.356 33.535 50.83 37.86 46.956C36.25 49.744 34.973 51.951 34.973 55.33C34.973 60.404 38.211 65.143 42.955 66.973C44.549 67.587 46.222 67.824 47.922 67.824C55.125 67.824 60.394 63.817 66.806 62.094C68.398 61.666 69.588 61.553 71.206 61.347Z"/><path fill="url(#m-bubble)" d="M72.336 41.925C77.122 41.925 81.257 45.674 81.257 50.54C81.257 55.583 76.554 58.82 71.902 58.82C67.179 58.82 63.019 55.302 63.019 50.453C63.019 45.66 67.675 41.925 72.336 41.925Z"/></svg><b>dsh-go</b></span><span data-i18n="share">\u5206\u4EAB</span></div>\r
  <section class="card" id="card" aria-live="polite">\r
    <div class="hero">\r
      <div class="tile" id="tile" aria-hidden="true"></div>\r
      <div>\r
        <h1 id="title" data-i18n="reading">\u6B63\u5728\u8BFB\u53D6\u2026</h1>\r
        <div class="sub" id="sub"></div>\r
      </div>\r
    </div>\r
    <p class="summary" id="summary" hidden></p>\r
    <ul class="facts" id="facts" hidden></ul>\r
    <div id="groups"></div>\r
    <div class="actions">\r
      <a class="btn primary" id="open" data-i18n="openApp" href="#" hidden>\u7528 dsh-go \u6253\u5F00</a>\r
      <a class="btn secondary" id="download" data-i18n="download" href="https://github.com/zheyuanAI/dsh-Go/releases/latest" rel="noopener">\u4E0B\u8F7D dsh-go</a>\r
    </div>\r
    <p class="note" id="note" hidden></p>\r
  </section>\r
</main>\r
<div id="dv-root" hidden></div>\r
<script src="viewer.js"><\/script>\r
<script src="share.js"><\/script>\r
</body>\r
</html>\r
`, "type": "text/html; charset=utf-8" }, "/share/share.js": { "body": `// dsh-go share landing page (docs/design/share-codes.md). Reads the share\r
// code from the URL fragment \u2014 which browsers never send to the server \u2014\r
// decodes it here, shows what it holds and hands it to the app as a\r
// dshgo:// link. Nothing is uploaded; only a Gist link fetches its Gist.\r
// Without a link the page opens conversation files (viewer.js).\r
//\r
// Code format (app/lib/share_code/share_codec.dart):\r
//   <base64url(deflate-raw(json))>.<base64url(sha256(json)[0..6])>\r
'use strict';\r
\r
(function () {\r
  var browserLanguage = typeof document !== 'undefined' && typeof navigator !== 'undefined' ? navigator.language || '' : '';\r
  var lang = !browserLanguage || /^zh/i.test(browserLanguage) ? 'zh' : 'en';\r
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';\r
  var I18N = {\r
    "zh": {\r
      "defaultModel": "\u9ED8\u8BA4\u6A21\u578B",\r
      "defaultPreset": "\u9ED8\u8BA4\u9884\u8BBE",\r
      "agent": "\u667A\u80FD\u4F53",\r
      "subagent": "\u5B50\u4EE3\u7406",\r
      "subagentModel": "\u5B50\u4EE3\u7406\u6A21\u578B",\r
      "deepseekModel": "DeepSeek \u6A21\u578B",\r
      "deepseekAccountModel": "DeepSeek \u8D26\u53F7\u6A21\u578B",\r
      "customProvider": "\u81EA\u5B9A\u4E49\u6A21\u578B\u670D\u52A1",\r
      "web": "\u8054\u7F51",\r
      "webSearch": "\u8054\u7F51\u641C\u7D22",\r
      "webSearchApi": "\u8054\u7F51\u641C\u7D22\u63A5\u53E3",\r
      "commands": "\u547D\u4EE4\u6267\u884C",\r
      "permissions": "\u6743\u9650",\r
      "chatLog": "\u5BF9\u8BDD\u65E5\u5FD7",\r
      "thinkingTranslation": "\u601D\u8003\u7FFB\u8BD1",\r
      "language": "\u8BED\u8A00",\r
      "webAppearance": "\u7F51\u9875\u7248\u5916\u89C2",\r
      "webChat": "\u7F51\u9875\u7248\u5BF9\u8BDD",\r
      "webInput": "\u7F51\u9875\u7248\u8F93\u5165",\r
      "dshOfficial": "DSH \u5B98\u65B9",\r
      "plugin": "\u63D2\u4EF6",\r
      "source": "\u6765\u6E90",\r
      "version": "\u7248\u672C",\r
      "checksum": "\u6821\u9A8C",\r
      "checksumIncluded": "\u9644\u5E26\u6821\u9A8C",\r
      "pluginSuffix": " \xB7 dsh-go \u63D2\u4EF6",\r
      "profile": "dsh-go \u914D\u7F6E",\r
      "official": "\u5B98\u65B9",\r
      "settings": "\u8BBE\u7F6E",\r
      "preset": "\u9884\u8BBE",\r
      "skill": "\u6280\u80FD",\r
      "globalInstructions": "\u5168\u5C40\u6307\u4EE4",\r
      "viewerTitle": "\u67E5\u770B\u5BF9\u8BDD \xB7 dsh-go",\r
      "incompleteLink": "\u8FD9\u4E2A\u94FE\u63A5\u4E0D\u5B8C\u6574",\r
      "wechatHint": "\u8BF7\u70B9\u53F3\u4E0A\u89D2\u300C\u2026\u300D\uFF0C\u5728\u6D4F\u89C8\u5668\u4E2D\u6253\u5F00",\r
      "shareTitle": "dsh-go \u5206\u4EAB",\r
      "viewInApp": "\u5728 dsh-go \u91CC\u67E5\u770B\u5185\u5BB9",\r
      "errorNewer": "\u9700\u8981\u66F4\u65B0 dsh-go \u624D\u80FD\u6253\u5F00",\r
      "errorGist": "\u6CA1\u80FD\u8BFB\u53D6\u8FD9\u4E2A Gist",\r
      "errorCode": "\u8FD9\u4E2A\u5206\u4EAB\u7801\u4E0D\u5B8C\u6574\u6216\u5DF2\u635F\u574F",\r
      "share": "\u5206\u4EAB",\r
      "reading": "\u6B63\u5728\u8BFB\u53D6\u2026",\r
      "openApp": "\u7528 dsh-go \u6253\u5F00",\r
      "download": "\u4E0B\u8F7D dsh-go",\r
      "plugins": "\u63D2\u4EF6",\r
      "presets": "\u9884\u8BBE",\r
      "skills": "\u6280\u80FD",\r
      "pluginCount": "{n} \u4E2A\u63D2\u4EF6",\r
      "settingCount": "{n} \u9879\u8BBE\u7F6E",\r
      "presetCount": "{n} \u4E2A\u9884\u8BBE",\r
      "skillCount": "{n} \u4E2A\u6280\u80FD",\r
      "itemCount": "{n} \u9879",\r
      "fileCount": "{n} \u4E2A\u6587\u4EF6",\r
      "lineCount": "{n} \u884C"\r
    },\r
    "en": {\r
      "defaultModel": "Default model",\r
      "defaultPreset": "Default preset",\r
      "agent": "Agent",\r
      "subagent": "Subagent",\r
      "subagentModel": "Subagent model",\r
      "deepseekModel": "DeepSeek model",\r
      "deepseekAccountModel": "DeepSeek account model",\r
      "customProvider": "Custom model provider",\r
      "web": "Web access",\r
      "webSearch": "Web search",\r
      "webSearchApi": "Web search API",\r
      "commands": "Command execution",\r
      "permissions": "Permissions",\r
      "chatLog": "Chat log",\r
      "thinkingTranslation": "Thinking translation",\r
      "language": "Language",\r
      "webAppearance": "DSH Web appearance",\r
      "webChat": "DSH Web chat",\r
      "webInput": "DSH Web input",\r
      "dshOfficial": "Official DSH",\r
      "plugin": "Plugin",\r
      "source": "Source",\r
      "version": "Version",\r
      "checksum": "Checksum",\r
      "checksumIncluded": "Checksum included",\r
      "pluginSuffix": " \xB7 dsh-go plugin",\r
      "profile": "dsh-go profile",\r
      "official": "Official",\r
      "settings": "Settings",\r
      "preset": "Preset",\r
      "skill": "Skill",\r
      "globalInstructions": "Global instructions",\r
      "viewerTitle": "View chat \xB7 dsh-go",\r
      "incompleteLink": "This link is incomplete",\r
      "wechatHint": "Tap \u201C\u2026\u201D at the top right, then open in your browser",\r
      "shareTitle": "dsh-go share",\r
      "viewInApp": "View this in dsh-go",\r
      "errorNewer": "Update dsh-go to open this",\r
      "errorGist": "Couldn\u2019t read this Gist",\r
      "errorCode": "This share code is incomplete or damaged",\r
      "share": "Share",\r
      "reading": "Reading\u2026",\r
      "openApp": "Open in dsh-go",\r
      "download": "Download dsh-go",\r
      "plugins": "Plugins",\r
      "presets": "Presets",\r
      "skills": "Skills",\r
      "pluginCount": {\r
        "one": "{n} plugin",\r
        "other": "{n} plugins"\r
      },\r
      "settingCount": {\r
        "one": "{n} setting",\r
        "other": "{n} settings"\r
      },\r
      "presetCount": {\r
        "one": "{n} preset",\r
        "other": "{n} presets"\r
      },\r
      "skillCount": {\r
        "one": "{n} skill",\r
        "other": "{n} skills"\r
      },\r
      "itemCount": {\r
        "one": "{n} item",\r
        "other": "{n} items"\r
      },\r
      "fileCount": {\r
        "one": "{n} file",\r
        "other": "{n} files"\r
      },\r
      "lineCount": {\r
        "one": "{n} line",\r
        "other": "{n} lines"\r
      }\r
    }\r
  };\r
\r
  function tr(key, values) {\r
    var value = I18N[lang][key];\r
    values = values || {};\r
    if (typeof value === 'object') value = value[values.n === 1 ? 'one' : 'other'];\r
    return value.replace(/\\{(\\w+)\\}/g, function (_, name) { return values[name]; });\r
  }\r
\r
  var APP_SCHEME = 'dshgo';\r
  var FORMAT_VERSION = 1;\r
  var MAX_BODY = 1024 * 1024;\r
\r
  var LABELS = {\r
    'agent-default-model': tr('defaultModel'),\r
    'agent-preset-registry': tr('defaultPreset'),\r
    'agent-loop': tr('agent'),\r
    'subagent': tr('subagent'),\r
    'subagent-model-selection-settings': tr('subagentModel'),\r
    'llm-deepseek': tr('deepseekModel'),\r
    'llm-deepseek-account': tr('deepseekAccountModel'),\r
    'llm-pi-ai': tr('customProvider'),\r
    'web': tr('web'),\r
    'web-search-deepseek': tr('webSearch'),\r
    'web-deepseek-api': tr('webSearchApi'),\r
    'bash-sandbox': tr('commands'),\r
    'permission': tr('permissions'),\r
    'session-log-deepseek': tr('chatLog'),\r
    'cot-translation': tr('thinkingTranslation'),\r
    'locale': tr('language'),\r
    'ui-theme': tr('webAppearance'),\r
    'ui-chat': tr('webChat'),\r
    'ui-conversation': tr('webInput')\r
  };\r
\r
  function $(id) { return document.getElementById(id); }\r
\r
  function text(el, value) { el.textContent = value; return el; }\r
\r
  function el(tag, cls, value) {\r
    var node = document.createElement(tag);\r
    if (cls) node.className = cls;\r
    if (value != null) node.textContent = value;\r
    return node;\r
  }\r
\r
  function b64urlToBytes(s) {\r
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('base64');\r
    var padded = s.replace(/-/g, '+').replace(/_/g, '/');\r
    while (padded.length % 4) padded += '=';\r
    var bin = atob(padded);\r
    var out = new Uint8Array(bin.length);\r
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\r
    return out;\r
  }\r
\r
  function bytesToB64url(bytes) {\r
    var bin = '';\r
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);\r
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');\r
  }\r
\r
  async function inflate(bytes) {\r
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));\r
    var reader = stream.getReader();\r
    var chunks = [];\r
    var total = 0;\r
    for (;;) {\r
      var r = await reader.read();\r
      if (r.done) break;\r
      total += r.value.length;\r
      if (total > MAX_BODY) { reader.cancel(); throw new Error('too large'); }\r
      chunks.push(r.value);\r
    }\r
    var out = new Uint8Array(total);\r
    var at = 0;\r
    chunks.forEach(function (c) { out.set(c, at); at += c.length; });\r
    return out;\r
  }\r
\r
  async function checksum(bytes) {\r
    var digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));\r
    return bytesToB64url(digest.slice(0, 6));\r
  }\r
\r
  /** The body of \`<data>.<sum>\`, checked. */\r
  async function decode(code) {\r
    var parts = code.split('.');\r
    if (parts.length !== 2 || !parts[0]) throw new Error('format');\r
    var body = await inflate(b64urlToBytes(parts[0]));\r
    if ((await checksum(body)) !== parts[1]) throw new Error('checksum');\r
    var json = JSON.parse(new TextDecoder().decode(body));\r
    if (!json || typeof json.v !== 'number' || json.v < 1) throw new Error('format');\r
    if (json.v > FORMAT_VERSION) throw new Error('newer');\r
    if (json.kind !== 'plugin' && json.kind !== 'profile') throw new Error('kind');\r
    return json;\r
  }\r
\r
  async function fetchGistCode(id, sum) {\r
    var res = await fetch('https://api.github.com/gists/' + encodeURIComponent(id), {\r
      headers: { Accept: 'application/vnd.github+json' },\r
      referrerPolicy: 'no-referrer',\r
      credentials: 'omit'\r
    });\r
    if (!res.ok) throw new Error('gist');\r
    var gist = await res.json();\r
    var files = gist && gist.files ? Object.values(gist.files) : [];\r
    for (var i = 0; i < files.length; i++) {\r
      var f = files[i];\r
      if (!f || typeof f.filename !== 'string' || !/\\.dshgo$/.test(f.filename)) continue;\r
      var content = f.content;\r
      if (f.truncated && typeof f.raw_url === 'string' && f.raw_url.indexOf('https://gist.githubusercontent.com/') === 0) {\r
        content = await (await fetch(f.raw_url, { referrerPolicy: 'no-referrer', credentials: 'omit' })).text();\r
      }\r
      var m = /"code"\\s*:\\s*"([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{8})"/.exec(content || '');\r
      if (m && m[1].slice(-sum.length - 1) === '.' + sum) return m[1];\r
    }\r
    throw new Error('gist');\r
  }\r
\r
  function str(v, max) {\r
    if (typeof v !== 'string') return null;\r
    var t = v.replace(/\\s+/g, ' ').trim();\r
    if (!t) return null;\r
    return t.length <= max ? t : t.slice(0, max - 1) + '\u2026';\r
  }\r
\r
  function sourceText(p) {\r
    var spec = String(p.spec || '');\r
    switch (p.source) {\r
      case 'npm': return 'npm';\r
      case 'github': {\r
        var m = /^github:([^/]+\\/[^#]+)#/.exec(spec) || /^git\\+https:\\/\\/github\\.com\\/([^/]+\\/[^#.]+)/.exec(spec);\r
        return 'GitHub' + (m ? ' \xB7 ' + m[1] : '');\r
      }\r
      case 'git': {\r
        var h = /^git\\+https:\\/\\/([^/]+)\\//.exec(spec);\r
        return h ? h[1] : 'Git';\r
      }\r
      case 'official': return tr('dshOfficial');\r
      default: return '\u2014';\r
    }\r
  }\r
\r
  function gitRef(spec) {\r
    var m = /#([A-Za-z0-9_./-]+)/.exec(String(spec || ''));\r
    return m ? m[1] : null;\r
  }\r
\r
  function addFact(label, value, chip) {\r
    var li = el('li');\r
    li.appendChild(el('span', null, label));\r
    li.appendChild(el('span', chip ? 'chip' : null, value));\r
    $('facts').appendChild(li);\r
    $('facts').hidden = false;\r
  }\r
\r
  function addGroup(title, rows) {\r
    if (!rows.length) return;\r
    var g = el('div', 'group');\r
    g.appendChild(el('h2', null, title));\r
    var ul = el('ul');\r
    rows.forEach(function (r) {\r
      var li = el('li');\r
      li.appendChild(el('span', r[2] ? 'mono' : null, r[0]));\r
      li.appendChild(el('span', null, r[1] || ''));\r
      ul.appendChild(li);\r
    });\r
    g.appendChild(ul);\r
    $('groups').appendChild(g);\r
  }\r
\r
  var PROFILE_ICON = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M3 17a1 1 0 0 1 1-1h5a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1Zm0-10a1 1 0 0 1 1-1h9a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1Zm10 12v-1h7a1 1 0 1 0 0-2h-7v-1a1 1 0 1 0-2 0v4a1 1 0 1 0 2 0ZM7 11v-1a1 1 0 1 1 2 0v4a1 1 0 1 1-2 0v-1H4a1 1 0 1 1 0-2h3Zm13 0a1 1 0 1 1 0 2h-9v-2h9ZM16 3a1 1 0 0 1 1 1v1h3a1 1 0 1 1 0 2h-3v1a1 1 0 1 1-2 0V4a1 1 0 0 1 1-1Z"/></svg>';\r
\r
  function showPlugin(body) {\r
    var p = body.plugin || {};\r
    var title = str(p.title, 80) || str(p.name, 214) || tr('plugin');\r
    text($('tile'), Array.from(title)[0].toUpperCase());\r
    text($('title'), title);\r
    text($('sub'), str(p.author, 80) || str(p.name, 214) || '');\r
    if (str(p.summary, 200)) { text($('summary'), str(p.summary, 200)); $('summary').hidden = false; }\r
    addFact(tr('source'), sourceText(p));\r
    addFact(tr('version'), str(p.version, 64) || gitRef(p.spec) || '\u2014');\r
    if (p.integrity) addFact(tr('checksum'), tr('checksumIncluded'), true);\r
    document.title = title + tr('pluginSuffix');\r
  }\r
\r
  function showProfile(body) {\r
    $('tile').innerHTML = PROFILE_ICON; // a constant, never data\r
    var title = str(body.name, 40) || tr('profile');\r
    text($('title'), title);\r
    var plugins = Array.isArray(body.plugins) ? body.plugins : [];\r
    var settings = body.settings && typeof body.settings === 'object' ? Object.keys(body.settings) : [];\r
    var presets = Array.isArray(body.presets) ? body.presets : [];\r
    var skills = Array.isArray(body.skills) ? body.skills : [];\r
    var parts = [];\r
    if (plugins.length) parts.push(tr('pluginCount', {n: plugins.length}));\r
    if (settings.length) parts.push(tr('settingCount', {n: settings.length}));\r
    if (presets.length) parts.push(tr('presetCount', {n: presets.length}));\r
    if (skills.length) parts.push(tr('skillCount', {n: skills.length}));\r
    if (typeof body.agentsMd === 'string') parts.push('AGENTS.md');\r
    text($('sub'), parts.join(' \xB7 '));\r
    addGroup(tr('plugins'), plugins.slice(0, 64).map(function (p) {\r
      return [str(p.title, 80) || str(p.name, 214) || tr('plugin'), p.source === 'official' ? tr('official') : (str(p.version, 64) || gitRef(p.spec))];\r
    }));\r
    addGroup(tr('settings'), settings.slice(0, 64).map(function (ns) {\r
      var values = body.settings[ns];\r
      var n = values && typeof values === 'object' ? Object.keys(values).length : 0;\r
      return [LABELS[ns] || ns, tr('itemCount', {n: n}), !LABELS[ns]];\r
    }));\r
    addGroup(tr('presets'), presets.slice(0, 64).map(function (p) { return [str(p.name, 60) || str(p.id, 64) || tr('preset'), '']; }));\r
    addGroup(tr('skills'), skills.slice(0, 32).map(function (s) {\r
      var n = s && s.files && typeof s.files === 'object' ? Object.keys(s.files).length : 0;\r
      return [str(s && s.name, 64) || tr('skill'), tr('fileCount', {n: n})];\r
    }));\r
    if (typeof body.agentsMd === 'string') addGroup(tr('globalInstructions'), [['AGENTS.md', tr('lineCount', {n: body.agentsMd.split('\\n').length})]]);\r
    document.title = title + ' \xB7 dsh-go';\r
  }\r
\r
  function fail(message) {\r
    text($('title'), message);\r
    text($('sub'), '');\r
    $('tile').textContent = '!';\r
    $('open').hidden = true;\r
  }\r
\r
  function note(message) {\r
    text($('note'), message);\r
    $('note').hidden = false;\r
  }\r
\r
  /** The conversation viewer takes the page (viewer.js). */\r
  function viewerPage() {\r
    document.querySelector('main').hidden = true;\r
    document.body.className = 'dv-page';\r
    var host = $('dv-root');\r
    host.hidden = false;\r
    return host;\r
  }\r
\r
  async function main() {\r
    var params = new URLSearchParams(location.hash.replace(/^#/, ''));\r
    var code = params.get('p');\r
    var gist = params.get('gist');\r
    var sum = params.get('c');\r
    var appLink = null;\r
    if (!code && !gist && window.DshgoViewer) {\r
      document.title = tr('viewerTitle');\r
      window.DshgoViewer.opener(viewerPage());\r
      return;\r
    }\r
    if (code && /^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{8}$/.test(code)) {\r
      appLink = null; // set once the kind is known\r
    } else if (gist && sum && /^[0-9a-f]{20,40}$/.test(gist) && /^[A-Za-z0-9_-]{8}$/.test(sum)) {\r
      appLink = APP_SCHEME + '://share/profile?gist=' + gist + '&c=' + sum;\r
    } else {\r
      fail(tr('incompleteLink'));\r
      return;\r
    }\r
    var openBtn = $('open');\r
    if (appLink) { openBtn.href = appLink; openBtn.hidden = false; }\r
    if (typeof navigator !== 'undefined' && /MicroMessenger/i.test(navigator.userAgent || '')) note(tr('wechatHint'));\r
\r
    if (typeof DecompressionStream === 'undefined' || !window.crypto || !crypto.subtle) {\r
      // Can't read it here; the app can.\r
      text($('title'), tr('shareTitle'));\r
      text($('sub'), tr('viewInApp'));\r
      if (code) { openBtn.href = APP_SCHEME + '://share/plugin?p=' + code; openBtn.hidden = false; }\r
      return;\r
    }\r
    try {\r
      if (!code) code = await fetchGistCode(gist, sum);\r
      var body = await decode(code);\r
      if (!appLink) {\r
        openBtn.href = APP_SCHEME + '://share/' + body.kind + '?p=' + code;\r
        openBtn.hidden = false;\r
      }\r
      if (body.kind === 'plugin') showPlugin(body); else showProfile(body);\r
    } catch (e) {\r
      var msg = String(e && e.message);\r
      fail(msg === 'newer' ? tr('errorNewer') : msg === 'gist' ? tr('errorGist') : tr('errorCode'));\r
    }\r
  }\r
\r
  document.title = tr('shareTitle');\r
  document.querySelectorAll('[data-i18n]').forEach(function (node) {\r
    node.textContent = tr(node.getAttribute('data-i18n'));\r
  });\r
  main();\r
})();\r
`, "type": "text/javascript; charset=utf-8" }, "/share/viewer.js": { "body": `// dsh-go conversation viewer (docs/design/share-codes.md). One source,\r
// three ways a conversation arrives ([boot]):\r
//\r
//   - a \`.dshgo\` file picked or dropped on the landing page (site/share/);\r
//   - the app's \u300C\u5BFC\u51FA\u4E3A\u7F51\u9875\u300D: this script inlined into one self-contained\r
//     page with the file in it (app/tool/make_replay_viewer.py \u2192\r
//     app/lib/share_code/replay_viewer.g.dart);\r
//   - a hosted link \`https://<host>/c/<id>#k=<key>\`: the page fetches\r
//     \`/api/v1/c/<id>\` and decrypts it here with the key after \`#\`, which the\r
//     browser never sends (AES-256-GCM, \`DSG1\` + IV + ciphertext, gzip inside).\r
//\r
// Reads a conversation share code (deflate-raw + SHA-256 checksum, the same\r
// format as app/lib/share_code/share_codec.dart), checks the pictures against\r
// their names, then renders and replays it. Nothing is uploaded or stored;\r
// data only ever reaches the page as text nodes and data: URLs.\r
'use strict';\r
\r
(function (root) {\r
  // A non-browser runtime may expose a default navigator; keep tests in Chinese.\r
  var browserLanguage = typeof document !== 'undefined' && typeof navigator !== 'undefined' ? navigator.language || '' : '';\r
  var lang = !browserLanguage || /^zh/i.test(browserLanguage) ? 'zh' : 'en';\r
  if (typeof document !== 'undefined' && document.documentElement) document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';\r
  var I18N = {\r
    "zh": {\r
      "chat": "\u5BF9\u8BDD",\r
      "copy": "\u590D\u5236",\r
      "copied": "\u5DF2\u590D\u5236",\r
      "allText": "\u5168\u6587",\r
      "progress": "\u56DE\u653E\u8FDB\u5EA6",\r
      "speed": "\u500D\u901F",\r
      "openApp": "\u7528 dsh-go \u6253\u5F00",\r
      "download": "\u4E0B\u8F7D dsh-go",\r
      "saveChat": "\u5B58\u4E3A\u5BF9\u8BDD\u6587\u4EF6",\r
      "pause": "\u6682\u505C",\r
      "replay": "\u91CD\u65B0\u64AD\u653E",\r
      "play": "\u64AD\u653E",\r
      "goalResume": "\u76EE\u6807\u7EED\u8DD1",\r
      "schedule": "\u5B9A\u65F6\u4EFB\u52A1",\r
      "auto": "\u81EA\u52A8",\r
      "image": "\u56FE\u7247",\r
      "thinkingActive": "\u601D\u8003\u4E2D",\r
      "thinking": "\u601D\u8003",\r
      "interrupted": "\u5DF2\u4E2D\u65AD",\r
      "declined": "\u5DF2\u62D2\u7EDD",\r
      "failed": "\u5931\u8D25",\r
      "cancelled": "\u5DF2\u53D6\u6D88",\r
      "outputCut": "\u8F93\u51FA\uFF08\u5DF2\u622A\u65AD\uFF09",\r
      "output": "\u8F93\u51FA",\r
      "stopped": "\u5DF2\u505C\u6B62",\r
      "error": "\u51FA\u9519\u4E86",\r
      "completed": "\u5DF2\u5B8C\u6210",\r
      "allDone": "\u5168\u90E8\u5B8C\u6210",\r
      "now": "\u6B63\u5728\uFF1A",\r
      "next": "\u4E0B\u4E00\u6B65\uFF1A",\r
      "goal": "\u76EE\u6807",\r
      "paused": "\u5DF2\u6682\u505C",\r
      "blocked": "\u53D7\u963B",\r
      "achieved": "\u5DF2\u8FBE\u6210",\r
      "pickFile": "\u9009\u62E9\u6587\u4EF6",\r
      "viewChat": "\u67E5\u770B\u5BF9\u8BDD",\r
      "pickHint": "\u9009\u62E9\u6216\u62D6\u5165 .dshgo \u6587\u4EF6",\r
      "fileTooLarge": "\u6587\u4EF6\u592A\u5927",\r
      "drop": "\u677E\u624B\u6253\u5F00",\r
      "opening": "\u6B63\u5728\u6253\u5F00\u2026",\r
      "errorNewer": "\u9700\u8981\u66F4\u65B0 dsh-go \u624D\u80FD\u6253\u5F00",\r
      "errorBrowser": "\u8FD9\u4E2A\u6D4F\u89C8\u5668\u6253\u4E0D\u5F00\uFF0C\u6362\u4E2A\u65B0\u7248\u6D4F\u89C8\u5668\u8BD5\u8BD5",\r
      "errorKind": "\u8FD9\u4E0D\u662F\u5BF9\u8BDD\u6587\u4EF6",\r
      "errorGone": "\u94FE\u63A5\u5DF2\u8FC7\u671F\u6216\u88AB\u5220\u9664",\r
      "errorNetwork": "\u6CA1\u80FD\u6253\u5F00\uFF0C\u68C0\u67E5\u7F51\u7EDC\u540E\u91CD\u8BD5",\r
      "errorKey": "\u94FE\u63A5\u4E0D\u5B8C\u6574",\r
      "errorFormat": "\u8FD9\u4E2A\u6587\u4EF6\u4E0D\u5B8C\u6574\u6216\u5DF2\u635F\u574F",\r
      "seconds": "{n} \u79D2",\r
      "minutes": "{n} \u5206\u949F",\r
      "hours": "{n} \u5C0F\u65F6",\r
      "date": "{year} \u5E74 {month} \u6708 {day} \u65E5",\r
      "turnRangeOne": "\u7B2C {from} \u8F6E\uFF0C\u5171 {total} \u8F6E",\r
      "turnRange": "\u7B2C {from}\u2013{to} \u8F6E\uFF0C\u5171 {total} \u8F6E",\r
      "steps": "{n} \u6B65",\r
      "toolCalls": "{n} \u6B21\u5DE5\u5177\u8C03\u7528",\r
      "messages": "{n} \u6761\u6D88\u606F",\r
      "thoughts": "{n} \u6BB5\u601D\u8003",\r
      "tokenCount": "{count} tokens",\r
      "viewerTitle": "\u67E5\u770B\u5BF9\u8BDD \xB7 dsh-go"\r
    },\r
    "en": {\r
      "chat": "Chat",\r
      "copy": "Copy",\r
      "copied": "Copied",\r
      "allText": "Full text",\r
      "progress": "Replay progress",\r
      "speed": "Speed",\r
      "openApp": "Open in dsh-go",\r
      "download": "Download dsh-go",\r
      "saveChat": "Save chat file",\r
      "pause": "Pause",\r
      "replay": "Replay",\r
      "play": "Play",\r
      "goalResume": "Goal resumed",\r
      "schedule": "Automation",\r
      "auto": "Automatic",\r
      "image": "Image",\r
      "thinkingActive": "Thinking\u2026",\r
      "thinking": "Thinking",\r
      "interrupted": "Interrupted",\r
      "declined": "Declined",\r
      "failed": "Failed",\r
      "cancelled": "Cancelled",\r
      "outputCut": "Output (truncated)",\r
      "output": "Output",\r
      "stopped": "Stopped",\r
      "error": "Something went wrong",\r
      "completed": "Completed",\r
      "allDone": "All done",\r
      "now": "Now: ",\r
      "next": "Next: ",\r
      "goal": "Goal",\r
      "paused": "Paused",\r
      "blocked": "Blocked",\r
      "achieved": "Achieved",\r
      "pickFile": "Choose file",\r
      "viewChat": "View chat",\r
      "pickHint": "Choose or drop a .dshgo file",\r
      "fileTooLarge": "File is too large",\r
      "drop": "Drop to open",\r
      "opening": "Opening\u2026",\r
      "errorNewer": "Update dsh-go to open this",\r
      "errorBrowser": "Can\u2019t open this in your browser. Try a newer one.",\r
      "errorKind": "This isn\u2019t a chat file",\r
      "errorGone": "This link has expired or was deleted",\r
      "errorNetwork": "Couldn\u2019t open. Check your network and try again.",\r
      "errorKey": "This link is incomplete",\r
      "errorFormat": "This file is incomplete or damaged",\r
      "seconds": "{n} s",\r
      "minutes": "{n} min",\r
      "hours": "{n} h",\r
      "date": "{year}-{month}-{day}",\r
      "turnRangeOne": "Turn {from} of {total}",\r
      "turnRange": "Turns {from}\u2013{to} of {total}",\r
      "steps": {\r
        "one": "{n} step",\r
        "other": "{n} steps"\r
      },\r
      "toolCalls": {\r
        "one": "{n} tool call",\r
        "other": "{n} tool calls"\r
      },\r
      "messages": {\r
        "one": "{n} message",\r
        "other": "{n} messages"\r
      },\r
      "thoughts": {\r
        "one": "{n} thought",\r
        "other": "{n} thoughts"\r
      },\r
      "tokenCount": {\r
        "one": "{count} token",\r
        "other": "{count} tokens"\r
      },\r
      "viewerTitle": "View chat \xB7 dsh-go"\r
    }\r
  };\r
\r
  function tr(key, values) {\r
    var value = I18N[lang][key];\r
    values = values || {};\r
    if (typeof value === 'object') value = value[values.n === 1 ? 'one' : 'other'];\r
    return value.replace(/\\{(\\w+)\\}/g, function (_, name) { return values[name]; });\r
  }\r
\r
  var BODY_VERSION = 2;\r
  var SCHEMA = 1;\r
  var MAX_BODY = 16 * 1024 * 1024;\r
  var MAX_SMALL_BODY = 1024 * 1024;\r
  var MAX_ENTRIES = 20000;\r
  var MAX_TEXT = 400000;\r
  var MAX_TOOL_TEXT = 64000;\r
  var IMAGE_TYPES = { 'image/jpeg': 1, 'image/png': 1, 'image/webp': 1, 'image/gif': 1 };\r
\r
  // \u2500\u2500 Decoding \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  function b64urlToBytes(s) {\r
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('format');\r
    var padded = s.replace(/-/g, '+').replace(/_/g, '/');\r
    while (padded.length % 4) padded += '=';\r
    var bin;\r
    try { bin = atob(padded); } catch (e) { throw new Error('format'); }\r
    var out = new Uint8Array(bin.length);\r
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\r
    return out;\r
  }\r
\r
  function b64ToBytes(s) {\r
    var bin = atob(s);\r
    var out = new Uint8Array(bin.length);\r
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);\r
    return out;\r
  }\r
\r
  function bytesToB64url(bytes) {\r
    var bin = '';\r
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);\r
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');\r
  }\r
\r
  async function inflate(bytes, limit) {\r
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));\r
    var reader = stream.getReader();\r
    var chunks = [];\r
    var total = 0;\r
    for (;;) {\r
      var r;\r
      try { r = await reader.read(); } catch (e) { throw new Error('format'); }\r
      if (r.done) break;\r
      total += r.value.length;\r
      if (total > limit) { reader.cancel(); throw new Error('format'); }\r
      chunks.push(r.value);\r
    }\r
    var out = new Uint8Array(total);\r
    var at = 0;\r
    chunks.forEach(function (c) { out.set(c, at); at += c.length; });\r
    return out;\r
  }\r
\r
  function canHash() { return !!(root.crypto && root.crypto.subtle); }\r
\r
  async function sha256(bytes) { return new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes)); }\r
\r
  /** The checked JSON object inside \`<data>.<sum>\`. Without SubtleCrypto\r
   *  (an old browser, a page opened from disk somewhere strict) the checksum\r
   *  can't be checked; [opts.trust] accepts the body then. */\r
  async function decodeCode(code, opts) {\r
    opts = opts || {};\r
    if (typeof DecompressionStream === 'undefined') throw new Error('browser');\r
    var parts = String(code).trim().split('.');\r
    if (parts.length !== 2 || !parts[0] || !/^[A-Za-z0-9_-]{8}$/.test(parts[1])) throw new Error('format');\r
    var body = await inflate(b64urlToBytes(parts[0]), MAX_BODY);\r
    if (canHash()) {\r
      if (bytesToB64url((await sha256(body)).slice(0, 6)) !== parts[1]) throw new Error('format');\r
    } else if (!opts.trust) {\r
      throw new Error('browser');\r
    }\r
    var json;\r
    try { json = JSON.parse(new TextDecoder().decode(body)); } catch (e) { throw new Error('format'); }\r
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('format');\r
    if (body.length > MAX_SMALL_BODY && json.kind !== 'conversation') throw new Error('format');\r
    return json;\r
  }\r
\r
  /** A \`.dshgo\` file's text (or a bare code): {code, kind, name, assets}. */\r
  function readEnvelope(text) {\r
    var t = String(text).trim();\r
    if (t.charAt(0) !== '{') return { code: t, assets: null };\r
    var json;\r
    try { json = JSON.parse(t); } catch (e) { throw new Error('format'); }\r
    if (!json || typeof json.dshgo !== 'number' || typeof json.code !== 'string') throw new Error('format');\r
    return {\r
      code: json.code,\r
      kind: typeof json.kind === 'string' ? json.kind : null,\r
      name: typeof json.name === 'string' ? json.name : null,\r
      assets: json.assets && typeof json.assets === 'object' ? json.assets : null\r
    };\r
  }\r
\r
  function num(v) { return typeof v === 'number' && isFinite(v) && v >= 0 ? Math.round(v) : null; }\r
\r
  function str(v, max) {\r
    if (typeof v !== 'string' || !v) return null;\r
    return v.length <= max ? v : v.slice(0, max) + '\u2026';\r
  }\r
\r
  function line(v, max) {\r
    if (typeof v !== 'string') return null;\r
    var t = v.replace(/\\s+/g, ' ').trim();\r
    if (!t) return null;\r
    return t.length <= max ? t : t.slice(0, max - 1) + '\u2026';\r
  }\r
\r
  function readEntry(e) {\r
    if (!e || typeof e !== 'object') throw new Error('format');\r
    var t = num(e.t) || 0;\r
    var d = num(e.d);\r
    switch (e.type) {\r
      case 'turn': return { type: 'turn', t: t, d: d, end: str(e.end, 32), steps: num(e.steps), tokens: num(e.tokens) };\r
      case 'user':\r
        return {\r
          type: 'user', t: t, text: str(e.text, MAX_TEXT) || '', source: str(e.source, 32),\r
          images: (Array.isArray(e.images) ? e.images.slice(0, 20) : []).filter(function (i) {\r
            return i && typeof i.id === 'string' && /^[A-Za-z0-9_-]{8,32}$/.test(i.id);\r
          }).map(function (i) { return { id: i.id, w: num(i.w), h: num(i.h), name: str(i.name, 200) }; }),\r
          files: (Array.isArray(e.files) ? e.files.slice(0, 20) : []).filter(function (f) {\r
            return f && str(f.name, 200);\r
          }).map(function (f) { return { name: str(f.name, 200), size: num(f.size) }; })\r
        };\r
      case 'reply':\r
        return { type: 'reply', t: t, d: d, text: str(e.text, MAX_TEXT) || '', think: str(e.think, MAX_TEXT), plain: str(e.plain, MAX_TEXT), model: str(e.model, 80), cut: e.cut === true };\r
      case 'tool':\r
        return {\r
          type: 'tool', t: t, d: d, name: str(e.name, 80) || 'tool', summary: str(e.summary, 500) || '', verb: str(e.verb, 40),\r
          status: ({ failed: 1, denied: 1, cancelled: 1 })[e.status] ? e.status : 'ok',\r
          result: str(e.result, MAX_TOOL_TEXT), more: num(e.more) || 0, error: str(e.error, 2000),\r
          args: e.args && typeof e.args === 'object' && !Array.isArray(e.args) ? e.args : {}\r
        };\r
      case 'notice': return { type: 'notice', t: t, kind: str(e.kind, 32) || 'error', text: str(e.text, 4000) || '' };\r
      case 'todos':\r
        return {\r
          type: 'todos', t: t,\r
          items: (Array.isArray(e.items) ? e.items.slice(0, 200) : []).filter(function (i) { return i && str(i.text, 500); })\r
            .map(function (i) { return { text: str(i.text, 500), status: str(i.status, 20) || 'pending' }; })\r
        };\r
      case 'goal': return { type: 'goal', t: t, text: str(e.text, 4000), phase: str(e.phase, 20) };\r
      case 'command': return { type: 'command', t: t, line: str(e.line, 2000) || '/', ok: e.ok !== false, text: str(e.text, 8000) };\r
      default: return null;\r
    }\r
  }\r
\r
  /** Validates a decoded conversation body (as ConversationShare.fromJson). */\r
  function readConversation(json) {\r
    if (typeof json.v !== 'number' || json.v < 1) throw new Error('format');\r
    if (json.v > BODY_VERSION) throw new Error('newer');\r
    if (json.kind !== 'conversation') throw new Error('kind');\r
    if (typeof json.schema !== 'number' || json.schema < 1) throw new Error('format');\r
    if (json.schema > SCHEMA) throw new Error('newer');\r
    var start = typeof json.start === 'string' ? Date.parse(json.start) : NaN;\r
    if (isNaN(start)) throw new Error('format');\r
    if (!Array.isArray(json.entries) || json.entries.length > MAX_ENTRIES) throw new Error('format');\r
    var entries = [];\r
    json.entries.forEach(function (e) { var r = readEntry(e); if (r) entries.push(r); });\r
    var range = json.range && num(json.range.from) && num(json.range.to) && num(json.range.of) ? json.range : null;\r
    return {\r
      title: line(json.title, 120) || tr('chat'),\r
      model: line(json.model, 80),\r
      app: line(json.app, 40),\r
      start: start,\r
      created: typeof json.created === 'string' ? Date.parse(json.created) : NaN,\r
      range: range,\r
      entries: entries\r
    };\r
  }\r
\r
  /** Pictures from \`assets\` that the conversation uses and whose bytes match\r
   *  their names, as data: URLs. */\r
  async function readAssets(raw, conv, opts) {\r
    var out = {};\r
    if (!raw) return out;\r
    var wanted = {};\r
    conv.entries.forEach(function (e) { if (e.type === 'user') e.images.forEach(function (i) { wanted[i.id] = 1; }); });\r
    var ids = Object.keys(raw);\r
    for (var k = 0; k < ids.length; k++) {\r
      var id = ids[k];\r
      var a = raw[id];\r
      if (!wanted[id] || !a || !IMAGE_TYPES[a.type] || typeof a.data !== 'string') continue;\r
      var bytes;\r
      try { bytes = b64ToBytes(a.data); } catch (e) { continue; }\r
      if (canHash()) {\r
        if (bytesToB64url((await sha256(bytes)).slice(0, 9)) !== id) continue;\r
      } else if (!(opts && opts.trust)) {\r
        continue;\r
      }\r
      out[id] = 'data:' + a.type + ';base64,' + a.data;\r
    }\r
    return out;\r
  }\r
\r
  /** A conversation from a \`.dshgo\` file's text (or a bare code). */\r
  async function openFile(text, opts) {\r
    var env = readEnvelope(text);\r
    var json = await decodeCode(env.code, opts);\r
    var conv = readConversation(json);\r
    return { conversation: conv, assets: await readAssets(env.assets, conv, opts), code: env.code };\r
  }\r
\r
\r
  // \u2500\u2500 Hosted links \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var MAGIC = [0x44, 0x53, 0x47, 0x31]; // "DSG1"\r
\r
  /** The \`.dshgo\` text inside a hosted blob: \`DSG1\` + 12-byte IV + AES-GCM\r
   *  ciphertext (tag included) of the gzipped file. */\r
  async function decryptHosted(buffer, keyText) {\r
    var bytes = new Uint8Array(buffer);\r
    if (bytes.length < 4 + 12 + 16) throw new Error('format');\r
    for (var i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) throw new Error('format');\r
    if (!canHash() || typeof DecompressionStream === 'undefined') throw new Error('browser');\r
    var raw;\r
    try { raw = b64urlToBytes(String(keyText || '')); } catch (e) { throw new Error('key'); }\r
    if (raw.length !== 32) throw new Error('key');\r
    var key = await root.crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);\r
    var plain;\r
    try {\r
      plain = await root.crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(4, 16) }, key, bytes.slice(16));\r
    } catch (e) {\r
      throw new Error('key');\r
    }\r
    var text;\r
    try {\r
      var stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));\r
      text = await new Response(stream).text();\r
    } catch (e) {\r
      throw new Error('format');\r
    }\r
    if (text.length > 64 * 1024 * 1024) throw new Error('format');\r
    return text;\r
  }\r
\r
  /** Fetches and opens a hosted conversation. */\r
  async function openHosted(id, keyText, fetchImpl) {\r
    var res;\r
    try {\r
      res = await (fetchImpl || root.fetch.bind(root))('/api/v1/c/' + encodeURIComponent(id), {\r
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'\r
      });\r
    } catch (e) {\r
      throw new Error('network');\r
    }\r
    if (res.status === 404 || res.status === 410) throw new Error('gone');\r
    if (!res.ok) throw new Error('network');\r
    var text = await decryptHosted(await res.arrayBuffer(), keyText);\r
    var opened = await openFile(text);\r
    opened.fileText = text;\r
    return opened;\r
  }\r
\r
  // \u2500\u2500 Replay pacing (app/lib/ui/replay/replay_timeline.dart) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var PACE = {\r
    gapKnee: 500, gapRate: 0.2, maxGap: 1600, maxGapBeforePrompt: 900,\r
    minStagger: 120, maxStagger: 400,\r
    fastestCps: 500, slowestCps: 30, maxStream: 6000, minStream: 300, assumedCps: 80,\r
    minThinking: 600, maxThinking: 2400,\r
    toolKnee: 300, toolRate: 0.15, minTool: 250, maxTool: 2500, assumedTool: 400,\r
    turnTail: 150\r
  };\r
\r
  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }\r
  function chars(s) { return s ? Array.from(s).length : 0; }\r
\r
  function gap(g, cap) {\r
    if (g <= 0) return 0;\r
    if (g <= PACE.gapKnee) return Math.min(g, cap);\r
    return Math.min(cap, PACE.gapKnee + (g - PACE.gapKnee) * PACE.gapRate);\r
  }\r
\r
  function origRun(e) { return (e.type === 'reply' || e.type === 'tool') ? (e.d || 0) : 0; }\r
\r
  function durations(e) {\r
    if (e.type === 'reply') {\r
      var textChars = chars(e.text);\r
      var thinkChars = chars(e.think);\r
      var total = textChars + thinkChars;\r
      if (total === 0) return [0, 0];\r
      var orig = e.d != null ? e.d : total / PACE.assumedCps * 1000;\r
      var thinkOrig = orig * thinkChars / total;\r
      var textOrig = orig - thinkOrig;\r
      var think = thinkChars === 0 ? 0 : clamp(thinkOrig, PACE.minThinking, PACE.maxThinking);\r
      if (textChars === 0) return [think, 0];\r
      var fastest = textChars / PACE.fastestCps * 1000;\r
      var slowest = textChars / PACE.slowestCps * 1000;\r
      var run = Math.min(PACE.maxStream, Math.max(fastest, Math.min(textOrig, slowest)));\r
      return [think, Math.max(run, PACE.minStream)];\r
    }\r
    if (e.type === 'tool') {\r
      if (e.d == null) return [0, PACE.assumedTool];\r
      var r = e.d <= PACE.toolKnee ? e.d : PACE.toolKnee + (e.d - PACE.toolKnee) * PACE.toolRate;\r
      return [0, clamp(r, PACE.minTool, PACE.maxTool)];\r
    }\r
    return [0, 0];\r
  }\r
\r
  /** {beats: [{start, think, end}], turnEnds: {index: time}, duration}. */\r
  function timeline(entries) {\r
    var beats = [];\r
    var lastEndOrig = 0, lastEndV = 0, prevStartOrig = 0, prevStartV = 0;\r
    entries.forEach(function (e, i) {\r
      var t = e.t;\r
      var dur = durations(e);\r
      var start;\r
      if (i === 0) start = 0;\r
      else if (t >= lastEndOrig) start = lastEndV + gap(t - lastEndOrig, e.type === 'user' || e.type === 'turn' ? PACE.maxGapBeforePrompt : PACE.maxGap);\r
      else start = prevStartV + clamp(t - prevStartOrig, PACE.minStagger, PACE.maxStagger);\r
      start = Math.max(start, prevStartV);\r
      var beat = { start: start, think: start + dur[0], end: start + dur[0] + dur[1] };\r
      beats.push(beat);\r
      prevStartOrig = t;\r
      prevStartV = start;\r
      if (e.type !== 'turn') {\r
        lastEndOrig = Math.max(lastEndOrig, t + origRun(e));\r
        lastEndV = Math.max(lastEndV, beat.end);\r
      }\r
    });\r
    var turnEnds = {};\r
    entries.forEach(function (e, i) {\r
      if (e.type !== 'turn' || e.d == null) return;\r
      var close = e.t + e.d;\r
      var end = beats[i].start;\r
      for (var j = i + 1; j < entries.length && entries[j].type !== 'turn'; j++) {\r
        if (entries[j].t > close) break;\r
        end = Math.max(end, beats[j].end);\r
      }\r
      turnEnds[i] = end + PACE.turnTail;\r
    });\r
    var duration = 0;\r
    beats.forEach(function (b) { duration = Math.max(duration, b.end); });\r
    Object.keys(turnEnds).forEach(function (k) { duration = Math.max(duration, turnEnds[k]); });\r
    return { beats: beats, turnEnds: turnEnds, duration: duration };\r
  }\r
\r
  // \u2500\u2500 DOM helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  function el(tag, cls, text) {\r
    var n = document.createElement(tag);\r
    if (cls) n.className = cls;\r
    if (text != null) n.textContent = text;\r
    return n;\r
  }\r
\r
  var SVG_NS = 'http://www.w3.org/2000/svg';\r
  var ICONS = {\r
    play: 'M8 5.6v12.8c0 .8.9 1.3 1.6.9l10-6.4c.6-.4.6-1.3 0-1.7l-10-6.4C8.9 4.3 8 4.8 8 5.6Z',\r
    pause: 'M7 5h3a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm7 0h3a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1h-3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z',\r
    replay: 'M12 5a7 7 0 1 1-7 7 1 1 0 1 1 2 0 5 5 0 1 0 1.6-3.7l1.1 1.1A.6.6 0 0 1 9.3 10.4H5.6A.6.6 0 0 1 5 9.8V6.1a.6.6 0 0 1 1-.4l1.2 1.2A7 7 0 0 1 12 5Z',\r
    chevron: 'M6.3 9.3a1 1 0 0 1 1.4 0L12 13.6l4.3-4.3a1 1 0 1 1 1.4 1.4l-5 5a1 1 0 0 1-1.4 0l-5-5a1 1 0 0 1 0-1.4Z',\r
    check: 'M9.5 16.2 5.8 12.5a1 1 0 0 0-1.4 1.4l4.4 4.4a1 1 0 0 0 1.4 0l9.6-9.6a1 1 0 0 0-1.4-1.4l-8.9 8.9Z',\r
    think: 'M12 3a6 6 0 0 0-3.6 10.8c.4.3.6.8.6 1.3V16a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1v-.9c0-.5.2-1 .6-1.3A6 6 0 0 0 12 3Zm-2 16a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2h-4Z',\r
    terminal: 'M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Zm2.3 4.3a1 1 0 0 0 0 1.4L9.6 12l-2.3 2.3a1 1 0 1 0 1.4 1.4l3-3a1 1 0 0 0 0-1.4l-3-3a1 1 0 0 0-1.4 0ZM13 14a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2h-4Z',\r
    read: 'M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm2 9a1 1 0 0 0 0 2h6a1 1 0 0 0 0-2H9Zm0 4a1 1 0 0 0 0 2h4a1 1 0 0 0 0-2H9Z',\r
    edit: 'M16.6 3.6a2 2 0 0 1 2.8 0l1 1a2 2 0 0 1 0 2.8L9.8 18 5 19l1-4.8L16.6 3.6Z',\r
    search: 'M10.5 4a6.5 6.5 0 0 1 5.2 10.4l3.9 3.9a1 1 0 0 1-1.4 1.4l-3.9-3.9A6.5 6.5 0 1 1 10.5 4Zm0 2a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z',\r
    web: 'M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18Zm-2.3 2.4A7 7 0 0 0 5.1 11h3a14 14 0 0 1 1.6-5.6Zm4.6 0A14 14 0 0 1 15.9 11h3a7 7 0 0 0-4.6-5.6ZM12 5.2A12 12 0 0 0 10.1 11h3.8A12 12 0 0 0 12 5.2ZM5.1 13a7 7 0 0 0 4.6 5.6A14 14 0 0 1 8.1 13h-3Zm5 0a12 12 0 0 0 1.9 5.8 12 12 0 0 0 1.9-5.8h-3.8Zm5.8 0a14 14 0 0 1-1.6 5.6 7 7 0 0 0 4.6-5.6h-3Z',\r
    agent: 'M12 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM6 14a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm12 0a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm-7-4h2v2.4l3.6 2.1-1 1.7L12 14l-3.6 2.2-1-1.7 3.6-2.1V10Z',\r
    plan: 'M9 4h6a1 1 0 0 1 1 1h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2a1 1 0 0 1 1-1Zm6.7 7.3a1 1 0 0 0-1.4 0L11 14.6l-1.3-1.3a1 1 0 0 0-1.4 1.4l2 2a1 1 0 0 0 1.4 0l4-4a1 1 0 0 0 0-1.4Z',\r
    tool: 'M14.7 3.3a5 5 0 0 0-5.6 6.9l-5.4 5.4a2 2 0 0 0 0 2.8l.9.9a2 2 0 0 0 2.8 0l5.4-5.4a5 5 0 0 0 6.9-5.6l-2.6 2.6-2.8-.7-.7-2.8 2.6-2.6Z',\r
    warn: 'M12 3.5c.7 0 1.3.4 1.7 1l7.1 12.4c.8 1.3-.2 3.1-1.7 3.1H4.9c-1.5 0-2.5-1.8-1.7-3.1L10.3 4.5c.4-.6 1-1 1.7-1Zm0 5a1 1 0 0 0-1 1v4a1 1 0 0 0 2 0v-4a1 1 0 0 0-1-1Zm0 7.5a1.2 1.2 0 1 0 0 2.4 1.2 1.2 0 0 0 0-2.4Z',\r
    file: 'M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm6 1.5V8a1 1 0 0 0 1 1h3.5L13 4.5Z',\r
    flag: 'M6 3a1 1 0 0 1 1 1v.3C8.2 3.8 9.8 3.6 12 4.4c2.6 1 4.4.6 6-.2a1 1 0 0 1 1.4.9v9a1 1 0 0 1-.6.9c-2 1-4.3 1.4-7.4.3-2.2-.8-3.9-.6-5.4.1V20a1 1 0 0 1-2 0V4a1 1 0 0 1 1-1Z'\r
  };\r
\r
  function icon(name, cls) {\r
    var svg = document.createElementNS(SVG_NS, 'svg');\r
    svg.setAttribute('viewBox', '0 0 24 24');\r
    svg.setAttribute('aria-hidden', 'true');\r
    if (cls) svg.setAttribute('class', cls);\r
    var path = document.createElementNS(SVG_NS, 'path');\r
    path.setAttribute('d', ICONS[name] || ICONS.tool);\r
    svg.appendChild(path);\r
    return svg;\r
  }\r
\r
  // \u2500\u2500 Markdown (a safe subset; streaming-tolerant) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var SAFE_URL = /^(https?:|mailto:)/i;\r
\r
  function inline(text, parent) {\r
    // Code spans first, then emphasis / links in the rest.\r
    var re = /(\`+)([\\s\\S]*?[^\`])\\1(?!\`)|\\*\\*([^*\\n]+)\\*\\*|__([^_\\n]+)__|~~([^~\\n]+)~~|\\*([^*\\s][^*\\n]*?)\\*|(?:^|(?<=[\\s(]))_([^_\\s][^_\\n]*?)_(?=$|[\\s).,!?;:])|\\[([^\\]\\n]+)\\]\\(([^()\\s]+)(?:\\s+"[^"]*")?\\)|(https?:\\/\\/[^\\s<>()]+[^\\s<>().,;:!?'"])|\\$([^$\\n]+)\\$/g;\r
    var at = 0;\r
    var m;\r
    while ((m = re.exec(text))) {\r
      if (m.index > at) parent.appendChild(document.createTextNode(text.slice(at, m.index)));\r
      if (m[1]) parent.appendChild(el('code', null, m[2]));\r
      else if (m[3] || m[4]) { var b = el('strong'); inline(m[3] || m[4], b); parent.appendChild(b); }\r
      else if (m[5]) { var s = el('del'); inline(m[5], s); parent.appendChild(s); }\r
      else if (m[6] || m[7]) { var i = el('em'); inline(m[6] || m[7], i); parent.appendChild(i); }\r
      else if (m[8]) {\r
        if (SAFE_URL.test(m[9])) {\r
          var a = el('a');\r
          a.href = m[9];\r
          a.target = '_blank';\r
          a.rel = 'noopener noreferrer nofollow';\r
          inline(m[8], a);\r
          parent.appendChild(a);\r
        } else {\r
          inline(m[8], parent);\r
        }\r
      } else if (m[10]) {\r
        var link = el('a', null, m[10]);\r
        link.href = m[10];\r
        link.target = '_blank';\r
        link.rel = 'noopener noreferrer nofollow';\r
        parent.appendChild(link);\r
      } else if (m[11]) parent.appendChild(el('span', 'dv-math', m[11]));\r
      at = re.lastIndex;\r
    }\r
    if (at < text.length) parent.appendChild(document.createTextNode(text.slice(at)));\r
  }\r
\r
  function paragraph(lines, parent) {\r
    var p = el('p');\r
    lines.forEach(function (l, i) {\r
      if (i > 0) p.appendChild(/ {2,}$|\\\\$/.test(lines[i - 1]) ? el('br') : document.createTextNode('\\n'));\r
      inline(l.replace(/\\\\$/, '').replace(/ {2,}$/, ''), p);\r
    });\r
    parent.appendChild(p);\r
  }\r
\r
  function splitRow(row) {\r
    var t = row.trim().replace(/^\\|/, '').replace(/\\|$/, '');\r
    return t.split(/(?<!\\\\)\\|/).map(function (c) { return c.trim().replace(/\\\\\\|/g, '|'); });\r
  }\r
\r
  function table(rows, parent) {\r
    var t = el('table');\r
    var head = el('thead');\r
    var tr = el('tr');\r
    splitRow(rows[0]).forEach(function (c) { var th = el('th'); inline(c, th); tr.appendChild(th); });\r
    head.appendChild(tr);\r
    t.appendChild(head);\r
    var body = el('tbody');\r
    rows.slice(2).forEach(function (r) {\r
      var row = el('tr');\r
      splitRow(r).forEach(function (c) { var td = el('td'); inline(c, td); row.appendChild(td); });\r
      body.appendChild(row);\r
    });\r
    t.appendChild(body);\r
    parent.appendChild(t);\r
  }\r
\r
  function list(lines, parent) {\r
    // lines: [{indent, ordered, text, start}]\r
    var stack = [];\r
    lines.forEach(function (item) {\r
      while (stack.length && item.indent < stack[stack.length - 1].indent) stack.pop();\r
      var top = stack[stack.length - 1];\r
      if (!top || item.indent > top.indent) {\r
        var listEl = el(item.ordered ? 'ol' : 'ul');\r
        if (item.ordered && item.start > 1) listEl.start = item.start;\r
        if (top && top.lastLi) top.lastLi.appendChild(listEl); else parent.appendChild(listEl);\r
        top = { indent: item.indent, el: listEl, lastLi: null };\r
        stack.push(top);\r
      }\r
      var li = el('li');\r
      inline(item.text, li);\r
      top.el.appendChild(li);\r
      top.lastLi = li;\r
    });\r
  }\r
\r
  function markdown(src, parent) {\r
    var lines = String(src).replace(/\\r\\n?/g, '\\n').split('\\n');\r
    var i = 0;\r
    var para = [];\r
    function flush() { if (para.length) { paragraph(para, parent); para = []; } }\r
    while (i < lines.length) {\r
      var l = lines[i];\r
      var fence = /^\\s{0,3}(\`{3,}|~{3,})\\s*([^\`\\s]*)?.*$/.exec(l);\r
      if (fence) {\r
        flush();\r
        var mark = fence[1];\r
        var lang = (fence[2] || '').toLowerCase();\r
        var body = [];\r
        i++;\r
        while (i < lines.length && !(lines[i].trim().indexOf(mark.charAt(0) === '\`' ? '\`\`\`' : '~~~') === 0 && lines[i].trim().replace(/[\`~]/g, '') === '')) {\r
          body.push(lines[i]);\r
          i++;\r
        }\r
        i++;\r
        if (lang === 'math' || lang === 'latex') { var mb = el('p', 'dv-math', body.join('\\n')); mb.style.whiteSpace = 'pre-wrap'; parent.appendChild(mb); }\r
        else parent.appendChild(codeBlock(body.join('\\n'), lang));\r
        continue;\r
      }\r
      if (/^\\s*\\$\\$\\s*$/.test(l)) {\r
        flush();\r
        var math = [];\r
        i++;\r
        while (i < lines.length && !/^\\s*\\$\\$\\s*$/.test(lines[i])) { math.push(lines[i]); i++; }\r
        i++;\r
        var mp = el('p', 'dv-math', math.join('\\n'));\r
        mp.style.whiteSpace = 'pre-wrap';\r
        parent.appendChild(mp);\r
        continue;\r
      }\r
      if (!l.trim()) { flush(); i++; continue; }\r
      var h = /^\\s{0,3}(#{1,6})\\s+(.*?)\\s*#*\\s*$/.exec(l);\r
      if (h) { flush(); var he = el('h' + h[1].length); inline(h[2], he); parent.appendChild(he); i++; continue; }\r
      if (/^\\s{0,3}([-*_])(\\s*\\1){2,}\\s*$/.test(l)) { flush(); parent.appendChild(el('hr')); i++; continue; }\r
      if (/^\\s{0,3}>/.test(l)) {\r
        flush();\r
        var quote = [];\r
        while (i < lines.length && /^\\s{0,3}>/.test(lines[i])) { quote.push(lines[i].replace(/^\\s{0,3}>\\s?/, '')); i++; }\r
        var bq = el('blockquote');\r
        markdown(quote.join('\\n'), bq);\r
        parent.appendChild(bq);\r
        continue;\r
      }\r
      if (/^\\s*\\|.*\\|\\s*$/.test(l) && i + 1 < lines.length && /^\\s*\\|?\\s*:?-{2,}:?\\s*(\\|\\s*:?-{2,}:?\\s*)*\\|?\\s*$/.test(lines[i + 1])) {\r
        flush();\r
        var rows = [];\r
        while (i < lines.length && /^\\s*\\|.*\\|?\\s*$/.test(lines[i]) && lines[i].trim()) { rows.push(lines[i]); i++; }\r
        table(rows, parent);\r
        continue;\r
      }\r
      var li = /^(\\s*)([-*+]|(\\d{1,9})[.)])\\s+(.*)$/.exec(l);\r
      if (li) {\r
        flush();\r
        var items = [];\r
        while (i < lines.length) {\r
          var m = /^(\\s*)([-*+]|(\\d{1,9})[.)])\\s+(.*)$/.exec(lines[i]);\r
          if (m) {\r
            items.push({ indent: m[1].replace(/\\t/g, '    ').length, ordered: !!m[3], start: m[3] ? parseInt(m[3], 10) : 1, text: m[4] });\r
            i++;\r
          } else if (lines[i].trim() && /^\\s{2,}/.test(lines[i]) && items.length) {\r
            items[items.length - 1].text += ' ' + lines[i].trim();\r
            i++;\r
          } else break;\r
        }\r
        list(items, parent);\r
        continue;\r
      }\r
      para.push(l);\r
      i++;\r
    }\r
    flush();\r
  }\r
\r
  /** Text cut mid-stream, closed for display: an open code span or bold. */\r
  function repairStream(text) {\r
    var lines = text.split('\\n');\r
    var fences = 0;\r
    lines.forEach(function (l) { if (/^\\s{0,3}(\`\`\`|~~~)/.test(l)) fences++; });\r
    if (fences % 2) return text; // inside a code block: shown as code already\r
    var last = lines[lines.length - 1];\r
    var ticks = (last.match(/\`/g) || []).length;\r
    if (ticks % 2) last += '\`';\r
    var stars = (last.match(/\\*\\*/g) || []).length;\r
    if (stars % 2) last += '**';\r
    lines[lines.length - 1] = last;\r
    return lines.join('\\n');\r
  }\r
\r
  /** The streaming caret at the end of the last text, however deep. */\r
  function caret(root) {\r
    var node = root;\r
    // Down through blocks only (the text after a bold run belongs to its\r
    // paragraph, not to the run).\r
    while (node.lastElementChild && /^(P|LI|OL|UL|BLOCKQUOTE|H[1-6]|DIV)$/.test(node.lastElementChild.tagName)) {\r
      node = node.lastElementChild;\r
    }\r
    if (node.classList.contains('dv-code')) node = node.querySelector('code') || node;\r
    node.appendChild(el('span', 'dv-caret'));\r
  }\r
\r
  // \u2500\u2500 Code highlighting (keywords, strings, comments, numbers) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var KW = {\r
    js: 'async await break case catch class const continue debugger default delete do else export extends finally for from function if import in instanceof let new of return static super switch this throw try typeof var void while with yield interface type enum implements private public protected readonly as',\r
    dart: 'abstract as assert async await break case catch class const continue default do else enum export extends extension external factory final finally for get if implements import in is late library mixin new on operator part required return sealed set static super switch sync this throw try typedef var void when while with yield base interface',\r
    py: 'and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case',\r
    sh: 'if then else elif fi for while do done case esac in function return export local readonly source echo cd exit set unset',\r
    go: 'break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var',\r
    rust: 'as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while',\r
    c: 'auto break case char class const continue default do double else enum extern float for goto if inline int long namespace new private protected public return short signed sizeof static struct switch template this throw try typedef typename union unsigned using virtual void volatile while bool fun val var when object package import override suspend data sealed is in out let guard func struct protocol extension',\r
    sql: 'select from where and or not insert into values update set delete create table alter drop index join left right inner outer on group by order having limit offset as distinct union all null is in like between case when then else end primary key references',\r
    css: 'important',\r
    yaml: 'true false null yes no on off'\r
  };\r
  var LIT = { 'true': 1, 'false': 1, 'null': 1, 'undefined': 1, 'None': 1, 'True': 1, 'False': 1, 'nil': 1 };\r
  var ALIAS = {\r
    javascript: 'js', jsx: 'js', ts: 'js', typescript: 'js', tsx: 'js', mjs: 'js', cjs: 'js', json: 'js', jsonc: 'js',\r
    python: 'py', py3: 'py', bash: 'sh', shell: 'sh', zsh: 'sh', console: 'sh', sh: 'sh', fish: 'sh', ps1: 'sh', powershell: 'sh',\r
    golang: 'go', rs: 'rust', cpp: 'c', 'c++': 'c', h: 'c', hpp: 'c', cs: 'c', csharp: 'c', java: 'c', kotlin: 'c', kt: 'c', swift: 'c', scala: 'c', php: 'c',\r
    yml: 'yaml', scss: 'css', less: 'css', postgres: 'sql', mysql: 'sql', sqlite: 'sql', dart: 'dart', go: 'go', rust: 'rust', c: 'c', sql: 'sql', css: 'css', yaml: 'yaml', js: 'js'\r
  };\r
\r
  function highlight(code, lang, parent) {\r
    var family = ALIAS[lang] || null;\r
    if (lang === 'diff' || lang === 'patch') {\r
      code.split('\\n').forEach(function (l, i) {\r
        if (i > 0) parent.appendChild(document.createTextNode('\\n'));\r
        var cls = /^\\+(?!\\+\\+)/.test(l) ? 'dv-add' : /^-(?!--)/.test(l) ? 'dv-del' : /^@@/.test(l) ? 'dv-t' : null;\r
        parent.appendChild(cls ? el('span', cls, l) : document.createTextNode(l));\r
      });\r
      return;\r
    }\r
    if (!family || code.length > 60000) { parent.textContent = code; return; }\r
    var hash = family === 'py' || family === 'sh' || family === 'yaml';\r
    var slash = family !== 'py' && family !== 'sh' && family !== 'yaml' && family !== 'sql';\r
    var words = {};\r
    (KW[family] || '').split(' ').forEach(function (w) { words[w] = 1; });\r
    var ci = family === 'sql';\r
    var re = new RegExp([\r
      slash ? '\\\\/\\\\/[^\\\\n]*|\\\\/\\\\*[\\\\s\\\\S]*?(?:\\\\*\\\\/|$)' : null,\r
      hash ? '#[^\\\\n]*' : null,\r
      family === 'sql' ? '--[^\\\\n]*' : null,\r
      family === 'py' ? '"""[\\\\s\\\\S]*?(?:"""|$)|\\'\\'\\'[\\\\s\\\\S]*?(?:\\'\\'\\'|$)' : null,\r
      '"(?:[^"\\\\\\\\\\\\n]|\\\\\\\\.)*"?|\\'(?:[^\\'\\\\\\\\\\\\n]|\\\\\\\\.)*\\'?|\`(?:[^\`\\\\\\\\]|\\\\\\\\.)*\`?',\r
      '\\\\b\\\\d[\\\\d_]*(?:\\\\.\\\\d+)?(?:[eE][+-]?\\\\d+)?\\\\b|\\\\b0x[\\\\da-fA-F]+\\\\b',\r
      '[A-Za-z_$][\\\\w$]*'\r
    ].filter(Boolean).join('|'), 'g');\r
    var at = 0;\r
    var m;\r
    while ((m = re.exec(code))) {\r
      if (m.index > at) parent.appendChild(document.createTextNode(code.slice(at, m.index)));\r
      var t = m[0];\r
      var c0 = t.charAt(0);\r
      var cls = null;\r
      if ((slash && (t.indexOf('//') === 0 || t.indexOf('/*') === 0)) || (hash && c0 === '#') || (family === 'sql' && t.indexOf('--') === 0)) cls = 'dv-c';\r
      else if (c0 === '"' || c0 === "'" || c0 === '\`') cls = 'dv-s';\r
      else if (/^\\d|^0x/.test(t)) cls = 'dv-n';\r
      else if (words[ci ? t.toLowerCase() : t]) cls = 'dv-k';\r
      else if (LIT[t]) cls = 'dv-n';\r
      else if (/^[A-Z]/.test(t) && family !== 'sh') cls = 'dv-t';\r
      else if (code.charAt(re.lastIndex) === '(') cls = 'dv-f';\r
      parent.appendChild(cls ? el('span', cls, t) : document.createTextNode(t));\r
      at = re.lastIndex;\r
    }\r
    if (at < code.length) parent.appendChild(document.createTextNode(code.slice(at)));\r
  }\r
\r
  function codeBlock(code, lang) {\r
    var wrap = el('div', 'dv-code');\r
    var head = el('div', 'dv-code-head');\r
    head.appendChild(el('span', null, lang || 'text'));\r
    var copy = el('button', null, tr('copy'));\r
    copy.type = 'button';\r
    copy.addEventListener('click', function () {\r
      if (typeof navigator !== 'undefined' && navigator.clipboard) navigator.clipboard.writeText(code).then(function () {\r
        copy.textContent = tr('copied');\r
        setTimeout(function () { copy.textContent = tr('copy'); }, 1400);\r
      }, function () {});\r
    });\r
    head.appendChild(copy);\r
    wrap.appendChild(head);\r
    var pre = el('pre');\r
    var c = el('code');\r
    highlight(code, lang, c);\r
    pre.appendChild(c);\r
    wrap.appendChild(pre);\r
    return wrap;\r
  }\r
\r
  // \u2500\u2500 Formatting \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  var TONES = {\r
    bash: 0, pwsh: 0, job_output: 0, job_list: 0, job_kill: 0,\r
    read: 1, read_image: 1, present: 1,\r
    write: 2, edit: 2, str_replace_editor: 2,\r
    grep: 3, glob: 3, web_fetch: 4, web_search: 4,\r
    subagent: 5, send_message: 5, interrupt_agent: 5, workflow: 5, ralph: 5, skill: 5,\r
    todo_write: 6, create_goal: 6, get_goal: 6, update_goal: 6, ask_user_question: 6\r
  };\r
  var TONE_ICON = ['terminal', 'read', 'edit', 'search', 'web', 'agent', 'plan', 'tool'];\r
  var CODE_TOOLS = { bash: 1, pwsh: 1, read: 1, write: 1, edit: 1, str_replace_editor: 1, read_image: 1, grep: 1, glob: 1, job_output: 1, job_kill: 1 };\r
\r
  function clock(ms) {\r
    var s = Math.max(0, Math.round(ms / 1000));\r
    var m = Math.floor(s / 60);\r
    s %= 60;\r
    return m + ':' + (s < 10 ? '0' : '') + s;\r
  }\r
\r
  function span(ms) {\r
    var s = Math.round(ms / 1000);\r
    if (s < 60) return tr('seconds', {n: Math.max(1, s)});\r
    var m = Math.round(s / 60);\r
    if (m < 60) return tr('minutes', {n: m});\r
    var h = Math.floor(m / 60);\r
    return tr('hours', {n: h}) + (m % 60 ? ' ' + tr('minutes', {n: m % 60}) : '');\r
  }\r
\r
  function tokens(n) {\r
    if (n < 1000) return n + '';\r
    if (n < 1000000) return (n / 1000).toFixed(n < 10000 ? 1 : 0).replace(/\\.0$/, '') + 'k';\r
    return (n / 1000000).toFixed(1).replace(/\\.0$/, '') + 'M';\r
  }\r
\r
  function bytes(n) {\r
    if (n == null) return '';\r
    if (n < 1024) return n + ' B';\r
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0).replace(/\\.0$/, '') + ' KB';\r
    return (n / 1024 / 1024).toFixed(1).replace(/\\.0$/, '') + ' MB';\r
  }\r
\r
  function prefix(text, f) {\r
    if (f >= 1) return text;\r
    if (f <= 0 || !text) return '';\r
    var a = Array.from(text);\r
    return a.slice(0, Math.floor(a.length * f)).join('');\r
  }\r
\r
  function modelName(id) {\r
    if (!id) return null;\r
    return id.replace(/^deepseek-/i, 'DeepSeek-').replace(/-v(\\d)/i, '-V$1').replace(/-pro$/i, '-Pro').replace(/-flash$/i, '-Flash');\r
  }\r
\r
  // \u2500\u2500 The viewer \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\r
\r
  /**\r
   * Mounts a conversation into [host]. opts: {assets, appLink, download,\r
   * autoplay (default true)}. Returns {play, pause, seek, showAll, destroy}.\r
   */\r
  function mount(host, conv, opts) {\r
    opts = opts || {};\r
    var assets = opts.assets || {};\r
    var entries = conv.entries;\r
    var plan = timeline(entries);\r
    var duration = plan.duration;\r
\r
    // Turn index of every entry (-1 before the first turn); a turn's parts.\r
    var turnOf = [];\r
    var current = -1;\r
    entries.forEach(function (e, i) { if (e.type === 'turn') current = i; turnOf.push(current); });\r
\r
    host.textContent = '';\r
    var page = el('div', 'dv');\r
    var bar = el('header', 'dv-bar');\r
    var barInner = el('div', 'dv-bar-inner');\r
    var head = el('div', 'dv-head');\r
    var headText = el('div', 'dv-head-text');\r
    var title = el('h1', 'dv-title', conv.title);\r
    var sub = el('div', 'dv-sub');\r
    var subParts = [];\r
    var started = new Date(conv.start);\r
    subParts.push(lang === 'zh' ? tr('date', {year: started.getFullYear(), month: started.getMonth() + 1, day: started.getDate()}) : started.toLocaleDateString('en', {year: 'numeric', month: 'short', day: 'numeric'}));\r
    if (conv.model) subParts.push(modelName(conv.model));\r
    var last = 0;\r
    entries.forEach(function (e) { last = Math.max(last, e.t + (e.d || 0)); });\r
    if (last > 0) subParts.push(span(last));\r
    if (conv.range) subParts.push(tr(conv.range.to === conv.range.from ? 'turnRangeOne' : 'turnRange', {from: conv.range.from, to: conv.range.to, total: conv.range.of}));\r
    sub.textContent = subParts.join(' \xB7 ');\r
    headText.appendChild(title);\r
    headText.appendChild(sub);\r
    head.appendChild(headText);\r
    var allBtn = el('button', 'dv-pill', tr('allText'));\r
    allBtn.type = 'button';\r
    head.appendChild(allBtn);\r
    barInner.appendChild(head);\r
\r
    var transport = el('div', 'dv-transport');\r
    var playBtn = el('button', 'dv-key');\r
    playBtn.type = 'button';\r
    var seek = el('input', 'dv-seek');\r
    seek.type = 'range';\r
    seek.min = '0';\r
    seek.max = String(Math.max(1, Math.round(duration)));\r
    seek.step = '1';\r
    seek.value = '0';\r
    seek.setAttribute('aria-label', tr('progress'));\r
    var time = el('span', 'dv-time');\r
    var speedBtn = el('button', 'dv-speed', '1\xD7');\r
    speedBtn.type = 'button';\r
    speedBtn.setAttribute('aria-label', tr('speed'));\r
    transport.appendChild(playBtn);\r
    transport.appendChild(seek);\r
    transport.appendChild(time);\r
    transport.appendChild(speedBtn);\r
    barInner.appendChild(transport);\r
    bar.appendChild(barInner);\r
    page.appendChild(bar);\r
\r
    var list = el('main', 'dv-list');\r
    list.setAttribute('aria-live', 'off');\r
    page.appendChild(list);\r
\r
    var bottom = el('div', 'dv-bottom');\r
    var bottomInner = el('div', 'dv-bottom-inner');\r
    var dock = el('div', 'dv-dock');\r
    dock.hidden = true;\r
    bottomInner.appendChild(dock);\r
    var actions = el('div', 'dv-actions');\r
    if (opts.appLink) {\r
      var open = el('a', 'dv-btn dv-primary', tr('openApp'));\r
      open.href = opts.appLink;\r
      actions.appendChild(open);\r
    }\r
    if (opts.download !== false) {\r
      var dl = el('a', 'dv-btn ' + (opts.appLink ? 'dv-secondary' : 'dv-primary'), tr('download'));\r
      dl.href = opts.download || 'https://github.com/zheyuanAI/dsh-Go/releases/latest';\r
      dl.rel = 'noopener';\r
      dl.target = '_blank';\r
      actions.appendChild(dl);\r
    }\r
    if (opts.fileText) {\r
      // The file itself, for replaying (and going on) in the app.\r
      var save = el('button', 'dv-btn dv-secondary', tr('saveChat'));\r
      save.type = 'button';\r
      save.addEventListener('click', function () {\r
        var url = URL.createObjectURL(new Blob([opts.fileText], { type: 'application/vnd.dshgo+json' }));\r
        var a = el('a');\r
        a.href = url;\r
        a.download = fileName(conv.title);\r
        document.body.appendChild(a);\r
        a.click();\r
        a.remove();\r
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);\r
      });\r
      actions.appendChild(save);\r
    }\r
    if (actions.childNodes.length) bottomInner.appendChild(actions);\r
    bottom.appendChild(bottomInner);\r
    page.appendChild(bottom);\r
    host.appendChild(page);\r
\r
    // \u2500\u2500 State \u2500\u2500\r
    var now = 0;\r
    var speed = 1;\r
    var playing = false;\r
    var raf = 0;\r
    var lastTick = 0;\r
    var follow = true;\r
    var rows = {};       // key \u2192 {el, sig}\r
    var openKeys = {};   // keys the reader opened\r
    var closedKeys = {}; // keys the reader closed (live groups)\r
    var todoOpen = false;\r
    var animate = false;\r
\r
    function setPlayIcon() {\r
      playBtn.textContent = '';\r
      var ended = now >= duration && !playing;\r
      playBtn.appendChild(icon(playing ? 'pause' : ended ? 'replay' : 'play'));\r
      playBtn.setAttribute('aria-label', playing ? tr('pause') : ended ? tr('replay') : tr('play'));\r
    }\r
\r
    function setClock() {\r
      seek.value = String(Math.round(now));\r
      seek.style.setProperty('--dv-p', (duration ? now / duration * 100 : 100) + '%');\r
      time.textContent = clock(now) + ' / ' + clock(duration);\r
    }\r
\r
    function turnClosed(ti) {\r
      var end = plan.turnEnds[ti];\r
      return end != null && now >= end;\r
    }\r
\r
    // \u2500\u2500 Rows \u2500\u2500\r
    function bubbleRow(e) {\r
      var row = el('div', 'dv-row dv-user');\r
      if (e.source && e.source !== 'user') row.appendChild(el('div', 'dv-source', e.source === 'goal' ? tr('goalResume') : e.source === 'schedule' ? tr('schedule') : tr('auto')));\r
      if (e.images.length) {\r
        var shots = el('div', 'dv-shots');\r
        var one = e.images.length === 1;\r
        e.images.forEach(function (img) {\r
          var url = assets[img.id];\r
          if (!url) { shots.appendChild(el('div', 'dv-shot dv-missing', tr('image'))); return; }\r
          var b = el('button', 'dv-shot ' + (one ? 'dv-one' : 'dv-many'));\r
          b.type = 'button';\r
          b.setAttribute('aria-label', img.name || tr('image'));\r
          var im = el('img');\r
          im.alt = img.name || tr('image');\r
          im.src = url;\r
          if (img.w && img.h) { im.width = img.w; im.height = img.h; }\r
          b.appendChild(im);\r
          b.addEventListener('click', function () { lightbox(url); });\r
          shots.appendChild(b);\r
        });\r
        row.appendChild(shots);\r
      }\r
      e.files.forEach(function (f) {\r
        var chip = el('div', 'dv-file');\r
        chip.appendChild(icon('file', 'dv-chev'));\r
        chip.appendChild(el('span', null, f.name));\r
        if (f.size != null) chip.appendChild(el('span', null, bytes(f.size)));\r
        row.appendChild(chip);\r
      });\r
      if (e.text.trim()) row.appendChild(el('div', 'dv-bubble', e.text));\r
      return row;\r
    }\r
\r
    function thinkRow(key, text, active, ms) {\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      var g = el('span', 'dv-glyph');\r
      g.style.background = 'var(--dv-t3)';\r
      g.style.color = 'var(--dv-o3)';\r
      g.appendChild(icon('think'));\r
      ln.appendChild(g);\r
      ln.appendChild(el('span', 'dv-label', active ? tr('thinkingActive') : tr('thinking')));\r
      ln.appendChild(el('span', 'dv-detail', text.replace(/\\s+/g, ' ').slice(0, 160)));\r
      if (active) ln.appendChild(el('span', 'dv-spin'));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      body.appendChild(el('div', 'dv-think', text));\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    function replyRow(e, text, streaming, done, foot) {\r
      var row = el('div', 'dv-row');\r
      var md = el('div', 'dv-md');\r
      markdown(streaming ? repairStream(text) : text, md);\r
      if (streaming) caret(md);\r
      row.appendChild(md);\r
      if (done && e.cut) row.appendChild(el('div', 'dv-cut', tr('interrupted')));\r
      if (foot) row.appendChild(el('div', 'dv-foot-note', foot));\r
      return row;\r
    }\r
\r
    function toolRow(key, e, running) {\r
      var bad = !running && (e.status === 'failed' || e.status === 'denied');\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      var tone = TONES[e.name] != null ? TONES[e.name] : 7;\r
      var g = el('span', 'dv-glyph');\r
      g.style.background = 'var(--dv-t' + tone + ')';\r
      g.style.color = 'var(--dv-o' + tone + ')';\r
      g.appendChild(icon(e.name.indexOf('mcp__') === 0 ? 'tool' : TONE_ICON[tone]));\r
      ln.appendChild(g);\r
      ln.appendChild(el('span', 'dv-label', e.verb || e.name));\r
      ln.appendChild(el('span', 'dv-detail' + (CODE_TOOLS[e.name] ? ' dv-mono' : ''), e.summary));\r
      if (running) ln.appendChild(el('span', 'dv-spin'));\r
      else if (bad) ln.appendChild(el('span', 'dv-state dv-bad', e.status === 'denied' ? tr('declined') : tr('failed')));\r
      else if (e.status === 'cancelled') ln.appendChild(el('span', 'dv-state', tr('cancelled')));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      var cmd = typeof e.args.command === 'string' ? e.args.command : null;\r
      if (cmd) body.appendChild(el('div', 'dv-out', '$ ' + cmd));\r
      else {\r
        var keys = Object.keys(e.args);\r
        if (keys.length) {\r
          var shown = {};\r
          keys.slice(0, 12).forEach(function (k) { shown[k] = e.args[k]; });\r
          var argText;\r
          try { argText = JSON.stringify(shown, null, 2); } catch (x) { argText = ''; }\r
          if (argText) body.appendChild(el('div', 'dv-out', argText));\r
        }\r
      }\r
      if (!running) {\r
        if (e.error) body.appendChild(el('div', 'dv-out', e.error));\r
        if (e.result) {\r
          body.appendChild(el('div', 'dv-out-label', e.more ? tr('outputCut') : tr('output')));\r
          body.appendChild(el('div', 'dv-out', e.result));\r
        }\r
      }\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    function toggle(ln, row, body, key) {\r
      function flip() {\r
        var open = body.hidden;\r
        body.hidden = !open;\r
        row.classList.toggle('dv-open', open);\r
        if (open) { openKeys[key] = 1; delete closedKeys[key]; } else { delete openKeys[key]; closedKeys[key] = 1; }\r
      }\r
      ln.addEventListener('click', flip);\r
      ln.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); flip(); } });\r
    }\r
\r
    function noticeRow(e) {\r
      var bad = e.kind === 'error' || e.kind === 'blocked';\r
      var row = el('div', 'dv-row dv-proc');\r
      var n = el('div', 'dv-notice' + (bad ? ' dv-bad' : ''));\r
      n.appendChild(icon('warn', 'dv-chev'));\r
      n.appendChild(el('span', null, e.text || (e.kind === 'aborted' ? tr('stopped') : tr('error'))));\r
      row.appendChild(n);\r
      return row;\r
    }\r
\r
    function commandRow(e) {\r
      var row = el('div', 'dv-row dv-proc');\r
      var c = el('div', 'dv-cmd', e.line);\r
      if (e.text) c.appendChild(el('span', null, '  ' + e.text.split('\\n')[0].slice(0, 200)));\r
      row.appendChild(c);\r
      return row;\r
    }\r
\r
    function footnote(turn) {\r
      var parts = [];\r
      if (turn.d != null) parts.push(span(turn.d));\r
      if (turn.steps) parts.push(tr('steps', {n: turn.steps}));\r
      if (turn.tokens) parts.push(tr('tokenCount', {n: turn.tokens, count: tokens(turn.tokens)}));\r
      return parts.join(' \xB7 ');\r
    }\r
\r
    function foldRow(key, tools, messages, thoughts, children) {\r
      var row = el('div', 'dv-row dv-proc' + (openKeys[key] ? ' dv-open' : ''));\r
      var ln = el('div', 'dv-line');\r
      ln.setAttribute('role', 'button');\r
      ln.tabIndex = 0;\r
      ln.appendChild(icon('check', 'dv-fold-ok'));\r
      var label = [tr('completed')];\r
      if (tools) label.push(tr('toolCalls', {n: tools}));\r
      if (messages) label.push(tr('messages', {n: messages}));\r
      if (!tools && !messages && thoughts) label.push(tr('thoughts', {n: thoughts}));\r
      ln.appendChild(el('span', 'dv-label', label.join(' \xB7 ')));\r
      ln.appendChild(el('span', 'dv-detail', ''));\r
      ln.appendChild(icon('chevron', 'dv-chev'));\r
      row.appendChild(ln);\r
      var body = el('div', 'dv-body');\r
      body.hidden = !openKeys[key];\r
      children.forEach(function (c) { c.classList.add('dv-quiet'); body.appendChild(c); });\r
      row.appendChild(body);\r
      toggle(ln, row, body, key);\r
      return row;\r
    }\r
\r
    // What the list shows at \`now\`: [{key, sig, build}].\r
    function model() {\r
      var out = [];\r
      var n = 0;\r
      while (n < plan.beats.length && plan.beats[n].start <= now) n++;\r
      var i = 0;\r
      while (i < n) {\r
        var e = entries[i];\r
        if (e.type === 'turn') {\r
          // The turn's parts up to the next turn (or what has appeared).\r
          var j = i + 1;\r
          while (j < n && entries[j].type !== 'turn') j++;\r
          var closed = turnClosed(i) && e.end === 'completed';\r
          if (closed) foldTurn(out, i, j); else liveRange(out, i + 1, j);\r
          if (turnClosed(i) && !closed) {\r
            var foot = footnote(e);\r
            if (foot) out.push(footPart(i, foot));\r
          }\r
          i = j;\r
        } else {\r
          var k = i + 1;\r
          while (k < n && entries[k].type !== 'turn') k++;\r
          liveRange(out, i, k);\r
          i = k;\r
        }\r
      }\r
      return out;\r
    }\r
\r
    function partOf(i) {\r
      var e = entries[i];\r
      var b = plan.beats[i];\r
      var done = now >= b.end;\r
      switch (e.type) {\r
        case 'user': return { key: 'u' + i, sig: '1', build: function () { return bubbleRow(e); } };\r
        case 'reply': {\r
          var parts = [];\r
          if (e.think) {\r
            var tActive = now < b.think;\r
            var tText = tActive ? prefix(e.think, (now - b.start) / Math.max(1, b.think - b.start)) : e.think;\r
            parts.push({ key: 'k' + i, sig: (tActive ? 'a' : 'd') + tText.length + (openKeys['k' + i] ? 'o' : ''), build: function () { return thinkRow('k' + i, tText, tActive, b.think - b.start); } });\r
          }\r
          var body = e.plain || e.text;\r
          if (body.trim() || (done && e.cut)) {\r
            var shown = done ? body : now < b.think ? '' : prefix(body, (now - b.think) / Math.max(1, b.end - b.think));\r
            if (shown || done) parts.push({ key: 'r' + i, sig: (done ? 'd' : 's') + shown.length, build: function () { return replyRow(e, shown, !done, done, null); } });\r
          }\r
          return parts;\r
        }\r
        case 'tool': return { key: 't' + i, sig: (done ? 'd' : 'r') + (openKeys['t' + i] ? 'o' : ''), build: function () { return toolRow('t' + i, e, !done); } };\r
        case 'notice': return { key: 'n' + i, sig: '1', build: function () { return noticeRow(e); } };\r
        case 'command': return { key: 'c' + i, sig: '1', build: function () { return commandRow(e); } };\r
        default: return null;\r
      }\r
    }\r
\r
    function liveRange(out, from, to) {\r
      for (var i = from; i < to; i++) {\r
        var p = partOf(i);\r
        if (!p) continue;\r
        if (Array.isArray(p)) p.forEach(function (x) { out.push(x); }); else out.push(p);\r
      }\r
    }\r
\r
    function foldTurn(out, ti, to) {\r
      // As the app's list: a turn folds only when it is one prompt's whole\r
      // turn (a message sent while it ran keeps it open).\r
      var prompts = 0;\r
      for (var u = ti + 1; u < to; u++) if (entries[u].type === 'user') prompts++;\r
      var foot = footnote(entries[ti]);\r
      if (prompts > 1) {\r
        liveRange(out, ti + 1, to);\r
        if (foot) out.push(footPart(ti, foot));\r
        return;\r
      }\r
      var first = ti + 1;\r
      if (first < to && entries[first].type === 'user') { out.push(partOf(first)); first++; }\r
      // The answer: the last reply with text, when no work follows it.\r
      var answer = -1;\r
      for (var i = to - 1; i >= first; i--) {\r
        var e = entries[i];\r
        if (e.type === 'reply' && (e.plain || e.text).trim()) { answer = i; break; }\r
        if (e.type === 'tool' || e.type === 'reply') break;\r
      }\r
      var processEnd = answer < 0 ? to : answer;\r
      var procParts = [];\r
      var kept = [];\r
      var tools = 0, messages = 0, thoughts = 0;\r
      for (var k = first; k < processEnd; k++) {\r
        var en = entries[k];\r
        if (en.type === 'user' || en.type === 'command') { kept.push(k); continue; }\r
        if (en.type === 'tool') tools++;\r
        if (en.type === 'reply') { if ((en.plain || en.text).trim()) messages++; if (en.think) thoughts++; }\r
        var p = partOf(k);\r
        if (!p) continue;\r
        if (Array.isArray(p)) p.forEach(function (x) { procParts.push(x); }); else procParts.push(p);\r
      }\r
      var answerThink = answer >= 0 && !!entries[answer].think;\r
      if (answerThink) thoughts++;\r
      var keptParts = kept.map(function (k) { return partOf(k); }).filter(Boolean);\r
      if (tools === 0 && messages === 0 && procParts.length + (answerThink ? 1 : 0) <= 1) {\r
        // A plain answer: its thinking pill is one line already.\r
        procParts.forEach(function (x) { out.push(x); });\r
        keptParts.forEach(function (x) { out.push(x); });\r
        if (answer >= 0) {\r
          if (answerThink) out.push(thinkPart(answer));\r
          out.push(answerPart(answer, foot));\r
        } else if (foot) out.push(footPart(ti, foot));\r
        return;\r
      }\r
      if (answerThink) procParts.push(thinkPart(answer));\r
      var key = 'f' + ti;\r
      var sig = 'f' + procParts.length + (openKeys[key] ? 'o' : '') + procParts.map(function (p) { return p.key + p.sig; }).join(',');\r
      out.push({\r
        key: key, sig: sig, build: function () {\r
          return foldRow(key, tools, messages, thoughts, procParts.map(function (p) { return p.build(); }));\r
        }\r
      });\r
      keptParts.forEach(function (x) { out.push(x); });\r
      if (answer >= 0) out.push(answerPart(answer, foot));\r
      else if (foot) out.push(footPart(ti, foot));\r
    }\r
\r
    function thinkPart(i) {\r
      var e = entries[i];\r
      return { key: 'k' + i, sig: 'd' + (openKeys['k' + i] ? 'o' : ''), build: function () { return thinkRow('k' + i, e.think, false, 0); } };\r
    }\r
\r
    function footPart(ti, foot) {\r
      return { key: 'ft' + ti, sig: foot, build: function () { var r = el('div', 'dv-row'); r.appendChild(el('div', 'dv-foot-note', foot)); return r; } };\r
    }\r
\r
    function answerPart(i, foot) {\r
      var e = entries[i];\r
      return { key: 'r' + i, sig: 'a' + (foot || ''), build: function () { return replyRow(e, e.plain || e.text, false, true, foot); } };\r
    }\r
\r
    // \u2500\u2500 Dock \u2500\u2500\r
    function renderDock() {\r
      var todos = null, goal = null, running = false;\r
      var n = 0;\r
      while (n < plan.beats.length && plan.beats[n].start <= now) {\r
        var e = entries[n];\r
        if (e.type === 'turn') { todos = null; if (!turnClosed(n)) running = true; }\r
        else if (e.type === 'todos') todos = e.items;\r
        else if (e.type === 'goal') goal = e.text ? e : null;\r
        n++;\r
      }\r
      var sig = JSON.stringify([todos, goal && goal.text, goal && goal.phase, running, todoOpen]);\r
      if (dock.dataset.sig === sig) return;\r
      dock.dataset.sig = sig;\r
      dock.textContent = '';\r
      dock.hidden = !(todos && todos.length) && !goal;\r
      if (todos && todos.length) {\r
        var done = todos.filter(function (t) { return t.status === 'completed'; }).length;\r
        var cur = todos.filter(function (t) { return t.status === 'in_progress'; })[0] || todos.filter(function (t) { return t.status !== 'completed'; })[0];\r
        var row = el('div', 'dv-dock-row');\r
        row.setAttribute('role', 'button');\r
        row.tabIndex = 0;\r
        var g = el('span', 'dv-glyph');\r
        g.style.background = 'var(--dv-t6)';\r
        g.style.color = 'var(--dv-o6)';\r
        g.appendChild(icon('plan'));\r
        row.appendChild(g);\r
        row.appendChild(el('b', null, done + '/' + todos.length));\r
        row.appendChild(el('span', 'dv-detail', done === todos.length ? tr('allDone') : ((running && cur.status === 'in_progress') ? tr('now') : tr('next')) + cur.text));\r
        row.appendChild(icon('chevron', 'dv-chev'));\r
        row.addEventListener('click', function () { todoOpen = !todoOpen; renderDock(); });\r
        dock.appendChild(row);\r
        if (todoOpen) {\r
          var ul = el('ul', 'dv-todos');\r
          todos.forEach(function (t) {\r
            ul.appendChild(el('li', t.status === 'completed' ? 'dv-done' : t.status === 'in_progress' ? 'dv-now' : null, t.text));\r
          });\r
          dock.appendChild(ul);\r
        }\r
      }\r
      if (goal) {\r
        var gr = el('div', 'dv-dock-row');\r
        var gg = el('span', 'dv-glyph');\r
        gg.style.background = 'var(--dv-t5)';\r
        gg.style.color = 'var(--dv-o5)';\r
        gg.appendChild(icon('flag'));\r
        gr.appendChild(gg);\r
        gr.appendChild(el('b', null, tr('goal')));\r
        gr.appendChild(el('span', 'dv-detail', goal.text.replace(/\\s+/g, ' ')));\r
        var phase = { paused: tr('paused'), blocked: tr('blocked'), complete: tr('achieved') }[goal.phase];\r
        if (phase) gr.appendChild(el('span', 'dv-state' + (goal.phase === 'blocked' ? ' dv-bad' : ''), phase));\r
        dock.appendChild(gr);\r
      }\r
    }\r
\r
    function render() {\r
      var want = model();\r
      var keep = {};\r
      var prev = null;\r
      want.forEach(function (w) {\r
        keep[w.key] = 1;\r
        var have = rows[w.key];\r
        if (!have || have.sig !== w.sig) {\r
          var node = w.build();\r
          if (!animate || have) node.classList.add('dv-quiet');\r
          if (have) list.replaceChild(node, have.el);\r
          rows[w.key] = have = { el: node, sig: w.sig };\r
        }\r
        var next = prev ? prev.nextSibling : list.firstChild;\r
        if (next !== have.el) list.insertBefore(have.el, next);\r
        prev = have.el;\r
      });\r
      Object.keys(rows).forEach(function (k) {\r
        if (!keep[k]) { if (rows[k].el.parentNode) rows[k].el.parentNode.removeChild(rows[k].el); delete rows[k]; }\r
      });\r
      renderDock();\r
      setClock();\r
      if (follow) window.scrollTo(0, document.documentElement.scrollHeight);\r
    }\r
\r
    function tick(ts) {\r
      raf = 0;\r
      if (!playing) return;\r
      var dt = lastTick ? Math.min(250, ts - lastTick) : 16;\r
      lastTick = ts;\r
      now = Math.min(duration, now + dt * speed);\r
      animate = true;\r
      render();\r
      if (now >= duration) { playing = false; setPlayIcon(); return; }\r
      raf = requestAnimationFrame(tick);\r
    }\r
\r
    function play() {\r
      if (now >= duration) { now = 0; follow = true; window.scrollTo(0, 0); }\r
      playing = true;\r
      lastTick = 0;\r
      setPlayIcon();\r
      if (!raf) raf = requestAnimationFrame(tick);\r
    }\r
\r
    function pause() {\r
      playing = false;\r
      if (raf) cancelAnimationFrame(raf);\r
      raf = 0;\r
      setPlayIcon();\r
    }\r
\r
    function seekTo(ms) {\r
      now = clamp(ms, 0, duration);\r
      animate = false;\r
      render();\r
      setPlayIcon();\r
    }\r
\r
    function showAll() {\r
      pause();\r
      follow = false;\r
      seekTo(duration);\r
      setPlayIcon();\r
    }\r
\r
    playBtn.addEventListener('click', function () { if (playing) pause(); else play(); });\r
    speedBtn.addEventListener('click', function () {\r
      speed = speed === 1 ? 2 : speed === 2 ? 4 : 1;\r
      speedBtn.textContent = speed + '\xD7';\r
    });\r
    seek.addEventListener('input', function () { follow = true; seekTo(Number(seek.value)); });\r
    allBtn.addEventListener('click', function () { showAll(); window.scrollTo(0, 0); });\r
    window.addEventListener('scroll', function () {\r
      var gapPx = document.documentElement.scrollHeight - (window.scrollY + window.innerHeight);\r
      follow = gapPx < 80;\r
    }, { passive: true });\r
    function onKey(ev) {\r
      if (ev.target && /INPUT|TEXTAREA|BUTTON|A/.test(ev.target.tagName)) return;\r
      if (ev.key === ' ') { ev.preventDefault(); if (playing) pause(); else play(); }\r
    }\r
    document.addEventListener('keydown', onKey);\r
\r
    setPlayIcon();\r
    render();\r
    if (opts.autoplay !== false && duration > 0) setTimeout(play, 500);\r
    else if (duration <= 0) showAll();\r
\r
    return {\r
      play: play, pause: pause, seek: seekTo, showAll: showAll,\r
      get time() { return now; }, get duration() { return duration; },\r
      destroy: function () { pause(); document.removeEventListener('keydown', onKey); host.textContent = ''; }\r
    };\r
  }\r
\r
  function lightbox(url) {\r
    var box = el('div', 'dv-lightbox');\r
    var im = el('img');\r
    im.src = url;\r
    im.alt = '';\r
    box.appendChild(im);\r
    box.addEventListener('click', function () { box.remove(); });\r
    document.addEventListener('keydown', function esc(ev) { if (ev.key === 'Escape') { box.remove(); document.removeEventListener('keydown', esc); } });\r
    (document.querySelector('.dv') || document.body).appendChild(box);\r
  }\r
\r
\r
  function fileName(title) {\r
    var base = String(title || tr('chat')).replace(/[\\\\/:*?"<>|\\u0000-\\u001f]+/g, ' ').trim().slice(0, 40) || tr('chat');\r
    return base + '.dshgo';\r
  }\r
\r
  function card(host, heading, text, button) {\r
    host.textContent = '';\r
    var page = el('div', 'dv');\r
    var c = el('section', 'dv-open-card');\r
    c.appendChild(el('h1', null, heading));\r
    if (text) c.appendChild(el('p', null, text));\r
    if (button) c.appendChild(button);\r
    page.appendChild(c);\r
    host.appendChild(page);\r
    return c;\r
  }\r
\r
  /** \u300C\u67E5\u770B\u5BF9\u8BDD\u300D: pick a \`.dshgo\` file or drop one anywhere on the page. */\r
  function opener(host, opts) {\r
    opts = opts || {};\r
    var input = el('input');\r
    input.type = 'file';\r
    input.accept = '.dshgo,application/vnd.dshgo+json,application/json';\r
    input.hidden = true;\r
    var pick = el('button', 'dv-btn dv-primary', tr('pickFile'));\r
    pick.type = 'button';\r
    pick.addEventListener('click', function () { input.click(); });\r
    var c = card(host, tr('viewChat'), tr('pickHint'), pick);\r
    c.appendChild(input);\r
    var error = el('p', 'dv-error');\r
    error.hidden = true;\r
    c.appendChild(error);\r
    async function take(file) {\r
      if (!file) return;\r
      if (file.size > 32 * 1024 * 1024) { error.textContent = tr('fileTooLarge'); error.hidden = false; return; }\r
      try {\r
        var text = await file.text();\r
        var opened = await openFile(text);\r
        mount(host, opened.conversation, { assets: opened.assets, fileText: text, download: opts.download });\r
        document.title = opened.conversation.title + ' \xB7 dsh-go';\r
        detachDrop();\r
      } catch (e) {\r
        error.textContent = errorText(e);\r
        error.hidden = false;\r
      }\r
    }\r
    input.addEventListener('change', function () { take(input.files && input.files[0]); });\r
    var shade = null;\r
    var depth = 0;\r
    function enter(ev) { ev.preventDefault(); depth++; if (!shade) { shade = el('div', 'dv-drop', tr('drop')); host.firstChild.appendChild(shade); } }\r
    function over(ev) { ev.preventDefault(); }\r
    function leave() { depth = Math.max(0, depth - 1); if (!depth && shade) { shade.remove(); shade = null; } }\r
    function drop(ev) {\r
      ev.preventDefault();\r
      depth = 0;\r
      if (shade) { shade.remove(); shade = null; }\r
      take(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]);\r
    }\r
    function detachDrop() {\r
      document.removeEventListener('dragenter', enter);\r
      document.removeEventListener('dragover', over);\r
      document.removeEventListener('dragleave', leave);\r
      document.removeEventListener('drop', drop);\r
    }\r
    document.addEventListener('dragenter', enter);\r
    document.addEventListener('dragover', over);\r
    document.addEventListener('dragleave', leave);\r
    document.addEventListener('drop', drop);\r
  }\r
\r
  /** Starts whichever page this is: the file inside it (the exported page),\r
   *  a hosted link, or the file opener. */\r
  async function boot(host) {\r
    host = host || document.getElementById('dv-root');\r
    var data = document.getElementById('dshgo-data');\r
    var embedded = data ? data.textContent.trim() : '';\r
    try {\r
      // The exported page has the file here; the template's own marker is\r
      // split so filling it in can't touch this line.\r
      if (embedded && embedded !== '__DSHGO_' + 'DATA__') {\r
        var opened = await openFile(embedded, { trust: true });\r
        mount(host, opened.conversation, { assets: opened.assets, fileText: embedded });\r
        return;\r
      }\r
      var path = /\\/c\\/([A-Za-z0-9]{6,32})\\/?$/.exec(location.pathname);\r
      if (path) {\r
        document.title = tr('viewerTitle');\r
        var key = new URLSearchParams(location.hash.replace(/^#/, '')).get('k');\r
        if (!key) throw new Error('key');\r
        card(host, tr('opening'), null, null);\r
        var hosted = await openHosted(path[1], key);\r
        document.title = hosted.conversation.title + ' \xB7 dsh-go';\r
        mount(host, hosted.conversation, {\r
          assets: hosted.assets,\r
          fileText: hosted.fileText,\r
          // The app opens the same link (the key stays in the fragment).\r
          appLink: 'dshgo://' + location.host + location.pathname + location.hash\r
        });\r
        return;\r
      }\r
      document.title = tr('viewerTitle');\r
      opener(host);\r
    } catch (e) {\r
      var dl = el('a', 'dv-btn dv-secondary', tr('download'));\r
      dl.href = 'https://github.com/zheyuanAI/dsh-Go/releases/latest';\r
      dl.rel = 'noopener';\r
      card(host, errorText(e), null, dl);\r
    }\r
  }\r
\r
  /** An error's short text. */\r
  function errorText(e) {\r
    var m = String(e && e.message);\r
    return m === 'newer' ? tr('errorNewer')\r
      : m === 'browser' ? tr('errorBrowser')\r
      : m === 'kind' ? tr('errorKind')\r
      : m === 'gone' ? tr('errorGone')\r
      : m === 'network' ? tr('errorNetwork')\r
      : m === 'key' ? tr('errorKey')\r
      : tr('errorFormat');\r
  }\r
\r
  root.DshgoViewer = {\r
    decodeCode: decodeCode,\r
    readEnvelope: readEnvelope,\r
    readConversation: readConversation,\r
    readAssets: readAssets,\r
    openFile: openFile,\r
    decryptHosted: decryptHosted,\r
    openHosted: openHosted,\r
    opener: opener,\r
    boot: boot,\r
    timeline: timeline,\r
    mount: mount,\r
    markdown: markdown,\r
    errorText: errorText,\r
    PACE: PACE\r
  };\r
})(typeof window !== 'undefined' ? window : globalThis);\r
`, "type": "text/javascript; charset=utf-8" }, "/share/viewer.css": { "body": `/* dsh-go conversation viewer (viewer.js). Shared by the landing page and the\r
   self-contained page the app exports (app/tool/make_replay_viewer.py inlines\r
   it). Colours follow the app's default theme (\u96FE\u84DD), light and dark. */\r
\r
.dv {\r
  --dv-bg-top: #ebf1fe;\r
  --dv-bg-bottom: #f6f7fc;\r
  --dv-ink: #1e232e;\r
  --dv-ink-2: #4f5562;\r
  --dv-ink-3: #646974;\r
  --dv-ink-4: #a1a5ac;\r
  --dv-line: rgba(11, 21, 45, 0.08);\r
  --dv-glass: rgba(255, 255, 255, 0.78);\r
  --dv-card: rgba(255, 255, 255, 0.62);\r
  --dv-solid: #fbfcff;\r
  --dv-bubble: #d9e4fd;\r
  --dv-primary: #4b67b4;\r
  --dv-on-primary: #ffffff;\r
  --dv-tint: rgba(30, 35, 46, 0.06);\r
  --dv-code-bg: #edf0f6;\r
  --dv-code-head: #e7ebf3;\r
  --dv-code-line: #dbdee5;\r
  --dv-danger: #a54743;\r
  --dv-success: #337250;\r
  --dv-warning: #936123;\r
  --dv-shadow: 0 8px 24px rgba(11, 21, 45, 0.08), 0 1px 3px rgba(11, 21, 45, 0.05);\r
  --dv-hl-k: #8e3e9e; --dv-hl-s: #2f7a4b; --dv-hl-c: #8a8f9a; --dv-hl-n: #9a5b13; --dv-hl-t: #2f5fb3; --dv-hl-f: #315aa8;\r
  /* Tool tones: terminal, read, edit, search, web, agent, plan, neutral. */\r
  --dv-t0: #e6eaf2; --dv-o0: #343d51;\r
  --dv-t1: #daecff; --dv-o1: #173f65;\r
  --dv-t2: #fae6cd; --dv-o2: #543600;\r
  --dv-t3: #ede5fe; --dv-o3: #443261;\r
  --dv-t4: #d7f1e2; --dv-o4: #034a2e;\r
  --dv-t5: #f9e2f0; --dv-o5: #582b4a;\r
  --dv-t6: #d0f1f0; --dv-o6: #004747;\r
  --dv-t7: #e7e9ef; --dv-o7: #363d4c;\r
  color: var(--dv-ink);\r
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "PingFang SC", "Noto Sans CJK SC", "Microsoft YaHei", "Segoe UI", sans-serif;\r
  -webkit-text-size-adjust: 100%;\r
}\r
@media (prefers-color-scheme: dark) {\r
  .dv {\r
    --dv-bg-top: #1d222c;\r
    --dv-bg-bottom: #1b1c23;\r
    --dv-ink: #e6e9f0;\r
    --dv-ink-2: #b6bbc5;\r
    --dv-ink-3: #9a9ea9;\r
    --dv-ink-4: #656971;\r
    --dv-line: rgba(255, 255, 255, 0.09);\r
    --dv-glass: rgba(43, 48, 60, 0.82);\r
    --dv-card: rgba(255, 255, 255, 0.05);\r
    --dv-solid: #232730;\r
    --dv-bubble: #293144;\r
    --dv-primary: #97b1f0;\r
    --dv-on-primary: #121c34;\r
    --dv-tint: rgba(255, 255, 255, 0.08);\r
    --dv-code-bg: #14171e;\r
    --dv-code-head: #1a1e26;\r
    --dv-code-line: #2f333a;\r
    --dv-danger: #e69089;\r
    --dv-success: #8bcca6;\r
    --dv-warning: #e6bd7c;\r
    --dv-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 1px 3px rgba(0, 0, 0, 0.25);\r
    --dv-hl-k: #deb2e9; --dv-hl-s: #9ad5a5; --dv-hl-c: #7c8089; --dv-hl-n: #e3be80; --dv-hl-t: #a0c6ff; --dv-hl-f: #87ade4;\r
    --dv-t0: #303540; --dv-o0: #d1d8e5;\r
    --dv-t1: #21374e; --dv-o1: #c0dbf8;\r
    --dv-t2: #443116; --dv-o2: #ebd3b4;\r
    --dv-t3: #39304b; --dv-o3: #dcd1f3;\r
    --dv-t4: #1d3d2d; --dv-o4: #bde2cd;\r
    --dv-t5: #452c3d; --dv-o5: #edcce1;\r
    --dv-t6: #0f3d3d; --dv-o6: #b3e2e1;\r
    --dv-t7: #32353d; --dv-o7: #d3d7e1;\r
  }\r
}\r
\r
.dv-page { margin: 0; min-height: 100vh; background: linear-gradient(180deg, var(--dv-bg-top), var(--dv-bg-bottom)) fixed; }\r
.dv *, .dv *::before, .dv *::after { box-sizing: border-box; }\r
.dv { min-height: 100vh; display: flex; flex-direction: column; background: linear-gradient(180deg, var(--dv-bg-top), var(--dv-bg-bottom)); }\r
/* Reset at zero specificity, so the component classes below win. */\r
.dv :where(button) { font: inherit; color: inherit; border: 0; background: none; padding: 0; cursor: pointer; -webkit-tap-highlight-color: transparent; }\r
.dv button:focus-visible, .dv a:focus-visible, .dv input:focus-visible { outline: 2px solid var(--dv-primary); outline-offset: 2px; }\r
.dv [hidden] { display: none !important; }\r
\r
/* \u2500\u2500 Top bar: title, then the transport capsule \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-bar {\r
  position: sticky; top: 0; z-index: 5;\r
  padding: max(12px, env(safe-area-inset-top)) 12px 10px;\r
  background: linear-gradient(180deg, var(--dv-bg-top) 70%, transparent);\r
}\r
.dv-bar-inner { max-width: 744px; margin: 0 auto; display: grid; gap: 10px; }\r
.dv-head { display: flex; align-items: center; gap: 12px; padding: 0 4px; min-width: 0; }\r
.dv-head-text { min-width: 0; flex: 1; }\r
.dv-title { margin: 0; font-size: 17px; line-height: 1.35; font-weight: 600; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow-wrap: anywhere; }\r
.dv-sub { font-size: 12px; line-height: 1.4; color: var(--dv-ink-3); margin-top: 2px; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\r
.dv-pill {\r
  flex: none; height: 36px; padding: 0 14px; border-radius: 999px; font-size: 14px; font-weight: 500;\r
  background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line);\r
  -webkit-backdrop-filter: blur(18px) saturate(1.3); backdrop-filter: blur(18px) saturate(1.3);\r
}\r
.dv-transport {\r
  display: flex; align-items: center; gap: 8px; height: 44px; padding: 4px; border-radius: 999px;\r
  background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line);\r
  -webkit-backdrop-filter: blur(18px) saturate(1.3); backdrop-filter: blur(18px) saturate(1.3);\r
}\r
.dv-key { flex: none; width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; background: var(--dv-tint); transition: transform 0.12s ease; }\r
.dv-key:active { transform: scale(0.94); }\r
.dv-key svg { width: 20px; height: 20px; fill: currentColor; }\r
.dv-speed { flex: none; min-width: 44px; height: 36px; padding: 0 10px; border-radius: 999px; background: var(--dv-tint); font-size: 14px; font-weight: 600; font-variant-numeric: tabular-nums; }\r
.dv-time { flex: none; font-size: 12px; color: var(--dv-ink-3); font-variant-numeric: tabular-nums; min-width: 72px; text-align: center; }\r
.dv-seek { flex: 1; min-width: 40px; height: 36px; margin: 0; background: transparent; -webkit-appearance: none; appearance: none; cursor: pointer; --dv-p: 0%; }\r
.dv-seek::-webkit-slider-runnable-track { height: 4px; border-radius: 2px; background: linear-gradient(90deg, var(--dv-primary) var(--dv-p), var(--dv-tint) var(--dv-p)); }\r
.dv-seek::-moz-range-track { height: 4px; border-radius: 2px; background: var(--dv-tint); }\r
.dv-seek::-moz-range-progress { height: 4px; border-radius: 2px; background: var(--dv-primary); }\r
.dv-seek::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; margin-top: -6px; border-radius: 50%; background: var(--dv-primary); border: 2px solid var(--dv-solid); box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2); }\r
.dv-seek::-moz-range-thumb { width: 14px; height: 14px; border-radius: 50%; background: var(--dv-primary); border: 2px solid var(--dv-solid); }\r
\r
/* \u2500\u2500 The conversation \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-list { flex: 1; width: 100%; max-width: 752px; margin: 0 auto; padding: 8px 16px 24px; }\r
.dv-row { margin-top: 8px; animation: dv-in 0.24s ease-out both; }\r
.dv-row.dv-quiet { animation: none; }\r
.dv-row.dv-user { margin-top: 24px; display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }\r
.dv-row.dv-user:first-child { margin-top: 4px; }\r
.dv-row.dv-proc + .dv-row.dv-proc { margin-top: 0; }\r
@keyframes dv-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }\r
@media (prefers-reduced-motion: reduce) { .dv-row { animation: none; } .dv-caret { animation: none !important; } }\r
\r
.dv-bubble { max-width: min(85%, 560px); padding: 10px 14px; border-radius: 20px; background: var(--dv-bubble); white-space: pre-wrap; overflow-wrap: anywhere; }\r
.dv-shots { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; max-width: 85%; }\r
.dv-shot { display: block; border-radius: 14px; overflow: hidden; background: var(--dv-tint); border: 0.5px solid var(--dv-line); }\r
.dv-shot img { display: block; width: 100%; height: 100%; object-fit: cover; }\r
.dv-shot.dv-one { max-width: 208px; max-height: 208px; }\r
.dv-shot.dv-one img { object-fit: contain; height: auto; max-height: 208px; }\r
.dv-shot.dv-many { width: 88px; height: 88px; }\r
.dv-shot.dv-missing { width: 88px; height: 88px; display: grid; place-items: center; color: var(--dv-ink-4); font-size: 12px; }\r
.dv-file { display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 14px; background: var(--dv-card); border: 0.5px solid var(--dv-line); font-size: 13px; }\r
.dv-file span:last-child { color: var(--dv-ink-3); }\r
.dv-source { font-size: 12px; color: var(--dv-ink-3); }\r
\r
/* Replies: full-width Markdown, no frame. */\r
.dv-md { overflow-wrap: anywhere; }\r
.dv-md > :first-child { margin-top: 0; }\r
.dv-md > :last-child { margin-bottom: 0; }\r
.dv-md p { margin: 0 0 12px; }\r
.dv-md h1, .dv-md h2, .dv-md h3, .dv-md h4, .dv-md h5, .dv-md h6 { margin: 20px 0 8px; line-height: 1.35; font-weight: 600; }\r
.dv-md h1 { font-size: 22px; } .dv-md h2 { font-size: 19px; } .dv-md h3 { font-size: 17px; } .dv-md h4, .dv-md h5, .dv-md h6 { font-size: 16px; }\r
.dv-md ul, .dv-md ol { margin: 0 0 12px; padding-left: 24px; }\r
.dv-md li { margin: 2px 0; }\r
.dv-md li > ul, .dv-md li > ol { margin: 2px 0 0; }\r
.dv-md blockquote { margin: 0 0 12px; padding: 0 0 0 12px; border-left: 3px solid var(--dv-line); color: var(--dv-ink-2); }\r
.dv-md hr { border: 0; border-top: 1px solid var(--dv-line); margin: 16px 0; }\r
.dv-md a { color: var(--dv-primary); text-decoration: none; }\r
.dv-md a:hover { text-decoration: underline; }\r
.dv-md code { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.86em; padding: 1px 5px; border-radius: 6px; background: var(--dv-code-bg); }\r
.dv-md table { border-collapse: collapse; margin: 0 0 12px; display: block; overflow-x: auto; max-width: 100%; font-size: 14px; }\r
.dv-md th, .dv-md td { border: 1px solid var(--dv-line); padding: 6px 10px; text-align: left; vertical-align: top; }\r
.dv-md th { font-weight: 600; background: var(--dv-tint); }\r
.dv-md .dv-math { font-family: "JetBrains Mono", ui-monospace, Menlo, monospace; font-size: 14px; color: var(--dv-ink-2); }\r
.dv-code { margin: 0 0 12px; border-radius: 14px; overflow: hidden; background: var(--dv-code-bg); border: 0.5px solid var(--dv-code-line); }\r
.dv-code-head { display: flex; align-items: center; justify-content: space-between; height: 36px; padding: 0 8px 0 14px; background: var(--dv-code-head); font-size: 12px; color: var(--dv-ink-3); }\r
.dv-code-head button { height: 28px; padding: 0 8px; border-radius: 8px; font-size: 12px; color: var(--dv-ink-3); }\r
.dv-code pre { margin: 0; padding: 12px 14px; overflow-x: auto; font: 13px/1.55 "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }\r
.dv-code pre code { padding: 0; background: none; font-size: inherit; border-radius: 0; }\r
.dv-k { color: var(--dv-hl-k); } .dv-s { color: var(--dv-hl-s); } .dv-c { color: var(--dv-hl-c); font-style: italic; }\r
.dv-n { color: var(--dv-hl-n); } .dv-t { color: var(--dv-hl-t); } .dv-f { color: var(--dv-hl-f); }\r
.dv-add { color: var(--dv-success); } .dv-del { color: var(--dv-danger); }\r
.dv-caret { display: inline-block; width: 8px; height: 1.05em; margin-left: 2px; vertical-align: -0.15em; border-radius: 2px; background: var(--dv-primary); animation: dv-blink 1s steps(2, start) infinite; }\r
@keyframes dv-blink { to { visibility: hidden; } }\r
.dv-cut { margin-top: 8px; font-size: 13px; color: var(--dv-danger); }\r
.dv-foot-note { margin-top: 4px; font-size: 12px; color: var(--dv-ink-3); font-variant-numeric: tabular-nums; }\r
\r
/* Process lines: thinking, tools, the folded turn. */\r
.dv-line { display: flex; align-items: center; gap: 8px; min-height: 32px; padding: 4px 0; font-size: 14px; color: var(--dv-ink-2); cursor: pointer; user-select: none; }\r
.dv-line .dv-label { flex: none; }\r
.dv-line .dv-detail { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dv-ink-3); }\r
.dv-line .dv-detail.dv-mono { font: 13px "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace; }\r
.dv-line .dv-state { flex: none; font-size: 12px; color: var(--dv-ink-3); }\r
.dv-line .dv-state.dv-bad { color: var(--dv-danger); }\r
.dv-chev { flex: none; width: 16px; height: 16px; fill: var(--dv-ink-3); transition: transform 0.2s ease; }\r
.dv-open > .dv-line .dv-chev { transform: rotate(180deg); }\r
.dv-glyph { flex: none; width: 22px; height: 22px; border-radius: 7px; display: grid; place-items: center; }\r
.dv-glyph svg { width: 13px; height: 13px; fill: currentColor; }\r
.dv-spin { flex: none; width: 14px; height: 14px; border-radius: 50%; border: 2px solid var(--dv-tint); border-top-color: var(--dv-primary); animation: dv-rot 0.8s linear infinite; }\r
@keyframes dv-rot { to { transform: rotate(360deg); } }\r
.dv-body { margin: 0 0 4px 10px; padding: 4px 0 4px 18px; border-left: 1.5px solid var(--dv-line); }\r
.dv-think { font-size: 14px; color: var(--dv-ink-3); white-space: pre-wrap; overflow-wrap: anywhere; }\r
.dv-out { margin: 4px 0; padding: 10px 12px; border-radius: 12px; background: var(--dv-code-bg); font: 12px/1.5 "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 320px; overflow: auto; color: var(--dv-ink-2); }\r
.dv-out-label { font-size: 12px; color: var(--dv-ink-3); margin-top: 6px; }\r
.dv-notice { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--dv-ink-3); padding: 4px 0; }\r
.dv-notice.dv-bad { color: var(--dv-danger); }\r
.dv-cmd { font: 13px "JetBrains Mono", ui-monospace, Menlo, monospace; color: var(--dv-ink-2); padding: 4px 0; }\r
.dv-cmd span { color: var(--dv-ink-3); font-family: inherit; }\r
.dv-fold-ok { flex: none; width: 16px; height: 16px; fill: var(--dv-success); }\r
\r
/* \u2500\u2500 Dock: todo list and goal, above the bottom actions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */\r
.dv-bottom { position: sticky; bottom: 0; z-index: 4; padding: 12px 12px max(12px, env(safe-area-inset-bottom)); background: linear-gradient(0deg, var(--dv-bg-bottom) 70%, transparent); }\r
.dv-bottom-inner { max-width: 744px; margin: 0 auto; display: grid; gap: 8px; }\r
.dv-dock { border-radius: 20px; background: var(--dv-glass); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line); -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px); overflow: hidden; }\r
.dv-dock-row { display: flex; align-items: center; gap: 8px; min-height: 40px; padding: 6px 14px; font-size: 13px; cursor: pointer; }\r
.dv-dock-row + .dv-dock-row { border-top: 0.5px solid var(--dv-line); }\r
.dv-dock-row b { font-weight: 600; font-variant-numeric: tabular-nums; }\r
.dv-dock-row .dv-detail { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dv-ink-2); }\r
.dv-todos { list-style: none; margin: 0; padding: 0 14px 10px 36px; font-size: 13px; max-height: 30vh; overflow: auto; }\r
.dv-todos li { padding: 3px 0; }\r
.dv-todos li.dv-done { color: var(--dv-ink-3); text-decoration: line-through; }\r
.dv-todos li.dv-now { font-weight: 600; }\r
.dv-actions { display: flex; gap: 12px; }\r
.dv-btn { flex: 1; display: flex; align-items: center; justify-content: center; height: 48px; border-radius: 999px; font-size: 16px; font-weight: 600; text-decoration: none; }\r
.dv-btn.dv-primary { background: var(--dv-primary); color: var(--dv-on-primary); }\r
.dv-btn.dv-secondary { color: var(--dv-ink); background: var(--dv-glass); border: 0.5px solid var(--dv-line); box-shadow: var(--dv-shadow); }\r
\r
/* Picture viewer. */\r
.dv-lightbox { position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; background: rgba(0, 0, 0, 0.86); padding: 16px; cursor: zoom-out; }\r
.dv-lightbox img { max-width: 100%; max-height: 100%; border-radius: 8px; }\r
\r
/* Opener (landing page without a link): pick or drop a file. */\r
.dv-open-card { width: calc(100% - 32px); max-width: 440px; margin: 15vh auto 0; padding: 32px 20px 24px; border-radius: 28px; background: var(--dv-solid); box-shadow: var(--dv-shadow); border: 0.5px solid var(--dv-line); text-align: center; }\r
.dv-open-card h1 { font-size: 21px; margin: 0 0 6px; font-weight: 600; }\r
.dv-open-card p { margin: 0 0 20px; color: var(--dv-ink-3); font-size: 14px; }\r
.dv-open-card .dv-btn { width: 100%; }\r
.dv-open-card .dv-error { color: var(--dv-danger); font-size: 13px; margin: 12px 0 0; }\r
.dv-drop { position: fixed; inset: 12px; z-index: 30; border-radius: 28px; border: 2px dashed var(--dv-primary); background: color-mix(in srgb, var(--dv-bg-top) 85%, transparent); display: grid; place-items: center; font-size: 17px; font-weight: 600; color: var(--dv-primary); pointer-events: none; }\r
\r
@media (max-width: 380px) {\r
  .dv-time { min-width: 0; font-size: 11px; }\r
  .dv-transport { gap: 6px; }\r
}\r
`, "type": "text/css; charset=utf-8" }, "/share/favicon.svg": { "body": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="18 18 72 72">\r\n<!-- dsh-go app tile, the favicon of the share page (same art as app/assets/brand/tile.svg). -->\r\n<defs><linearGradient id="tile-bg" gradientUnits="userSpaceOnUse" x1="7.57" y1="-5.87" x2="100.43" y2="113.87"><stop offset="0" stop-color="#9AB0E8"/><stop offset="1" stop-color="#405AAD"/></linearGradient><linearGradient id="tail" gradientUnits="userSpaceOnUse" x1="36.3" y1="57" x2="66.5" y2="40"><stop offset="0" stop-color="#8FAFFA"/><stop offset="1" stop-color="#DDEEFD"/></linearGradient><linearGradient id="fin" gradientUnits="userSpaceOnUse" x1="40.2" y1="41.5" x2="28.1" y2="39.4"><stop offset="0" stop-color="#8EADFB"/><stop offset="1" stop-color="#CDE2FB"/></linearGradient><radialGradient id="belly" gradientUnits="userSpaceOnUse" cx="0" cy="0" r="1" gradientTransform="matrix(27 0 0 13.5 52.7 71)"><stop offset="0" stop-color="#BFCCFA"/><stop offset="0.6" stop-color="#CCD8FB"/><stop offset="1" stop-color="#ECEAFE"/></radialGradient><radialGradient id="bubble" gradientUnits="userSpaceOnUse" cx="74.773" cy="47.737" r="11.858"><stop offset="0" stop-color="#A6C3FA"/><stop offset="0.55" stop-color="#B7CCFA"/><stop offset="1" stop-color="#ECE5FC"/></radialGradient></defs>\r\n<path id="tile" fill="url(#tile-bg)" d="M34.58 18C31.39 18.13 29.27 18.57 27.14 19.54C23.87 21.03 21.03 23.87 19.54 27.14C18.57 29.27 18.13 31.39 18 34.58C18 34.58 18 73.42 18 73.42C18.13 76.61 18.57 78.73 19.54 80.86C21.03 84.13 23.87 86.97 27.14 88.46C29.27 89.43 31.39 89.87 34.58 90C34.58 90 73.42 90 73.42 90C76.61 89.87 78.73 89.43 80.86 88.46C84.13 86.97 86.97 84.13 88.46 80.86C89.43 78.73 89.87 76.61 90 73.42C90 73.42 90 34.58 90 34.58C89.87 31.39 89.43 29.27 88.46 27.14C86.97 23.87 84.13 21.03 80.86 19.54C78.73 18.57 76.61 18.13 73.42 18C73.42 18 34.58 18 34.58 18Z"/>\r\n<path id="body" fill="url(#tail)" d="M41.533 42.237C44.542 35.225 52.318 30.559 59.471 28.765C60.371 28.538 62.707 28.015 63.555 28.015C64.422 28.015 64.421 28.514 64.421 29.29C64.421 31.68 63.303 34.553 62.143 36.621C55.998 47.579 48.019 44.056 43.838 46.999C43.15 47.483 42.766 48.054 42.766 48.912C42.766 50.39 43.965 52.011 44.897 53.082C45.928 54.267 47.16 55.238 48.469 56.094C55.176 60.483 63.472 60.609 71.206 61.347C74.082 61.621 79.534 62.636 79.534 66.422C79.534 68.215 78.222 70.141 77.075 71.438C71.344 77.92 61.895 80.004 53.58 80.004C44.713 80.004 35.314 77.576 31.142 68.924C30.012 66.582 29.365 64.181 29.365 61.571C29.365 55.356 33.535 50.83 37.86 46.956C38.345 46.522 38.831 46.123 39.305 45.676C38.855 45.728 38.235 45.778 37.786 45.778C33.274 45.778 29.511 43.364 27.53 39.337C27.273 38.812 26.75 37.645 26.75 37.084C26.75 36.858 26.762 36.709 26.938 36.537C27.598 35.893 30.489 35.739 31.449 35.739C34.863 35.739 39.247 36.73 40.913 40.064C41.275 40.789 41.476 41.422 41.533 42.237Z"/><path id="fin-layer" fill="url(#fin)" d="M39.305 45.676C38.855 45.728 38.235 45.778 37.786 45.778C33.274 45.778 29.511 43.364 27.53 39.337C27.273 38.812 26.75 37.645 26.75 37.084C26.75 36.858 26.762 36.709 26.938 36.537C27.598 35.893 30.489 35.739 31.449 35.739C34.863 35.739 39.247 36.73 40.913 40.064C41.275 40.789 41.476 41.422 41.533 42.237C40.939 43.623 40.431 44.616 39.305 45.676Z"/><path id="belly-layer" fill="url(#belly)" d="M71.206 61.347C74.082 61.621 79.534 62.636 79.534 66.422C79.534 68.215 78.222 70.141 77.075 71.438C71.344 77.92 61.895 80.004 53.58 80.004C44.713 80.004 35.314 77.576 31.142 68.924C30.012 66.582 29.365 64.181 29.365 61.571C29.365 55.356 33.535 50.83 37.86 46.956C36.25 49.744 34.973 51.951 34.973 55.33C34.973 60.404 38.211 65.143 42.955 66.973C44.549 67.587 46.222 67.824 47.922 67.824C55.125 67.824 60.394 63.817 66.806 62.094C68.398 61.666 69.588 61.553 71.206 61.347Z"/><path id="bubble-layer" fill="url(#bubble)" d="M72.336 41.925C77.122 41.925 81.257 45.674 81.257 50.54C81.257 55.583 76.554 58.82 71.902 58.82C67.179 58.82 63.019 55.302 63.019 50.453C63.019 45.66 67.675 41.925 72.336 41.925Z"/>\r\n</svg>\r\n', "type": "image/svg+xml" }, "/license": { "body": `                    GNU AFFERO GENERAL PUBLIC LICENSE\r
                       Version 3, 19 November 2007\r
\r
 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>\r
 Everyone is permitted to copy and distribute verbatim copies\r
 of this license document, but changing it is not allowed.\r
\r
                            Preamble\r
\r
  The GNU Affero General Public License is a free, copyleft license for\r
software and other kinds of works, specifically designed to ensure\r
cooperation with the community in the case of network server software.\r
\r
  The licenses for most software and other practical works are designed\r
to take away your freedom to share and change the works.  By contrast,\r
our General Public Licenses are intended to guarantee your freedom to\r
share and change all versions of a program--to make sure it remains free\r
software for all its users.\r
\r
  When we speak of free software, we are referring to freedom, not\r
price.  Our General Public Licenses are designed to make sure that you\r
have the freedom to distribute copies of free software (and charge for\r
them if you wish), that you receive source code or can get it if you\r
want it, that you can change the software or use pieces of it in new\r
free programs, and that you know you can do these things.\r
\r
  Developers that use our General Public Licenses protect your rights\r
with two steps: (1) assert copyright on the software, and (2) offer\r
you this License which gives you legal permission to copy, distribute\r
and/or modify the software.\r
\r
  A secondary benefit of defending all users' freedom is that\r
improvements made in alternate versions of the program, if they\r
receive widespread use, become available for other developers to\r
incorporate.  Many developers of free software are heartened and\r
encouraged by the resulting cooperation.  However, in the case of\r
software used on network servers, this result may fail to come about.\r
The GNU General Public License permits making a modified version and\r
letting the public access it on a server without ever releasing its\r
source code to the public.\r
\r
  The GNU Affero General Public License is designed specifically to\r
ensure that, in such cases, the modified source code becomes available\r
to the community.  It requires the operator of a network server to\r
provide the source code of the modified version running there to the\r
users of that server.  Therefore, public use of a modified version, on\r
a publicly accessible server, gives the public access to the source\r
code of the modified version.\r
\r
  An older license, called the Affero General Public License and\r
published by Affero, was designed to accomplish similar goals.  This is\r
a different license, not a version of the Affero GPL, but Affero has\r
released a new version of the Affero GPL which permits relicensing under\r
this license.\r
\r
  The precise terms and conditions for copying, distribution and\r
modification follow.\r
\r
                       TERMS AND CONDITIONS\r
\r
  0. Definitions.\r
\r
  "This License" refers to version 3 of the GNU Affero General Public License.\r
\r
  "Copyright" also means copyright-like laws that apply to other kinds of\r
works, such as semiconductor masks.\r
\r
  "The Program" refers to any copyrightable work licensed under this\r
License.  Each licensee is addressed as "you".  "Licensees" and\r
"recipients" may be individuals or organizations.\r
\r
  To "modify" a work means to copy from or adapt all or part of the work\r
in a fashion requiring copyright permission, other than the making of an\r
exact copy.  The resulting work is called a "modified version" of the\r
earlier work or a work "based on" the earlier work.\r
\r
  A "covered work" means either the unmodified Program or a work based\r
on the Program.\r
\r
  To "propagate" a work means to do anything with it that, without\r
permission, would make you directly or secondarily liable for\r
infringement under applicable copyright law, except executing it on a\r
computer or modifying a private copy.  Propagation includes copying,\r
distribution (with or without modification), making available to the\r
public, and in some countries other activities as well.\r
\r
  To "convey" a work means any kind of propagation that enables other\r
parties to make or receive copies.  Mere interaction with a user through\r
a computer network, with no transfer of a copy, is not conveying.\r
\r
  An interactive user interface displays "Appropriate Legal Notices"\r
to the extent that it includes a convenient and prominently visible\r
feature that (1) displays an appropriate copyright notice, and (2)\r
tells the user that there is no warranty for the work (except to the\r
extent that warranties are provided), that licensees may convey the\r
work under this License, and how to view a copy of this License.  If\r
the interface presents a list of user commands or options, such as a\r
menu, a prominent item in the list meets this criterion.\r
\r
  1. Source Code.\r
\r
  The "source code" for a work means the preferred form of the work\r
for making modifications to it.  "Object code" means any non-source\r
form of a work.\r
\r
  A "Standard Interface" means an interface that either is an official\r
standard defined by a recognized standards body, or, in the case of\r
interfaces specified for a particular programming language, one that\r
is widely used among developers working in that language.\r
\r
  The "System Libraries" of an executable work include anything, other\r
than the work as a whole, that (a) is included in the normal form of\r
packaging a Major Component, but which is not part of that Major\r
Component, and (b) serves only to enable use of the work with that\r
Major Component, or to implement a Standard Interface for which an\r
implementation is available to the public in source code form.  A\r
"Major Component", in this context, means a major essential component\r
(kernel, window system, and so on) of the specific operating system\r
(if any) on which the executable work runs, or a compiler used to\r
produce the work, or an object code interpreter used to run it.\r
\r
  The "Corresponding Source" for a work in object code form means all\r
the source code needed to generate, install, and (for an executable\r
work) run the object code and to modify the work, including scripts to\r
control those activities.  However, it does not include the work's\r
System Libraries, or general-purpose tools or generally available free\r
programs which are used unmodified in performing those activities but\r
which are not part of the work.  For example, Corresponding Source\r
includes interface definition files associated with source files for\r
the work, and the source code for shared libraries and dynamically\r
linked subprograms that the work is specifically designed to require,\r
such as by intimate data communication or control flow between those\r
subprograms and other parts of the work.\r
\r
  The Corresponding Source need not include anything that users\r
can regenerate automatically from other parts of the Corresponding\r
Source.\r
\r
  The Corresponding Source for a work in source code form is that\r
same work.\r
\r
  2. Basic Permissions.\r
\r
  All rights granted under this License are granted for the term of\r
copyright on the Program, and are irrevocable provided the stated\r
conditions are met.  This License explicitly affirms your unlimited\r
permission to run the unmodified Program.  The output from running a\r
covered work is covered by this License only if the output, given its\r
content, constitutes a covered work.  This License acknowledges your\r
rights of fair use or other equivalent, as provided by copyright law.\r
\r
  You may make, run and propagate covered works that you do not\r
convey, without conditions so long as your license otherwise remains\r
in force.  You may convey covered works to others for the sole purpose\r
of having them make modifications exclusively for you, or provide you\r
with facilities for running those works, provided that you comply with\r
the terms of this License in conveying all material for which you do\r
not control copyright.  Those thus making or running the covered works\r
for you must do so exclusively on your behalf, under your direction\r
and control, on terms that prohibit them from making any copies of\r
your copyrighted material outside their relationship with you.\r
\r
  Conveying under any other circumstances is permitted solely under\r
the conditions stated below.  Sublicensing is not allowed; section 10\r
makes it unnecessary.\r
\r
  3. Protecting Users' Legal Rights From Anti-Circumvention Law.\r
\r
  No covered work shall be deemed part of an effective technological\r
measure under any applicable law fulfilling obligations under article\r
11 of the WIPO copyright treaty adopted on 20 December 1996, or\r
similar laws prohibiting or restricting circumvention of such\r
measures.\r
\r
  When you convey a covered work, you waive any legal power to forbid\r
circumvention of technological measures to the extent such circumvention\r
is effected by exercising rights under this License with respect to\r
the covered work, and you disclaim any intention to limit operation or\r
modification of the work as a means of enforcing, against the work's\r
users, your or third parties' legal rights to forbid circumvention of\r
technological measures.\r
\r
  4. Conveying Verbatim Copies.\r
\r
  You may convey verbatim copies of the Program's source code as you\r
receive it, in any medium, provided that you conspicuously and\r
appropriately publish on each copy an appropriate copyright notice;\r
keep intact all notices stating that this License and any\r
non-permissive terms added in accord with section 7 apply to the code;\r
keep intact all notices of the absence of any warranty; and give all\r
recipients a copy of this License along with the Program.\r
\r
  You may charge any price or no price for each copy that you convey,\r
and you may offer support or warranty protection for a fee.\r
\r
  5. Conveying Modified Source Versions.\r
\r
  You may convey a work based on the Program, or the modifications to\r
produce it from the Program, in the form of source code under the\r
terms of section 4, provided that you also meet all of these conditions:\r
\r
    a) The work must carry prominent notices stating that you modified\r
    it, and giving a relevant date.\r
\r
    b) The work must carry prominent notices stating that it is\r
    released under this License and any conditions added under section\r
    7.  This requirement modifies the requirement in section 4 to\r
    "keep intact all notices".\r
\r
    c) You must license the entire work, as a whole, under this\r
    License to anyone who comes into possession of a copy.  This\r
    License will therefore apply, along with any applicable section 7\r
    additional terms, to the whole of the work, and all its parts,\r
    regardless of how they are packaged.  This License gives no\r
    permission to license the work in any other way, but it does not\r
    invalidate such permission if you have separately received it.\r
\r
    d) If the work has interactive user interfaces, each must display\r
    Appropriate Legal Notices; however, if the Program has interactive\r
    interfaces that do not display Appropriate Legal Notices, your\r
    work need not make them do so.\r
\r
  A compilation of a covered work with other separate and independent\r
works, which are not by their nature extensions of the covered work,\r
and which are not combined with it such as to form a larger program,\r
in or on a volume of a storage or distribution medium, is called an\r
"aggregate" if the compilation and its resulting copyright are not\r
used to limit the access or legal rights of the compilation's users\r
beyond what the individual works permit.  Inclusion of a covered work\r
in an aggregate does not cause this License to apply to the other\r
parts of the aggregate.\r
\r
  6. Conveying Non-Source Forms.\r
\r
  You may convey a covered work in object code form under the terms\r
of sections 4 and 5, provided that you also convey the\r
machine-readable Corresponding Source under the terms of this License,\r
in one of these ways:\r
\r
    a) Convey the object code in, or embodied in, a physical product\r
    (including a physical distribution medium), accompanied by the\r
    Corresponding Source fixed on a durable physical medium\r
    customarily used for software interchange.\r
\r
    b) Convey the object code in, or embodied in, a physical product\r
    (including a physical distribution medium), accompanied by a\r
    written offer, valid for at least three years and valid for as\r
    long as you offer spare parts or customer support for that product\r
    model, to give anyone who possesses the object code either (1) a\r
    copy of the Corresponding Source for all the software in the\r
    product that is covered by this License, on a durable physical\r
    medium customarily used for software interchange, for a price no\r
    more than your reasonable cost of physically performing this\r
    conveying of source, or (2) access to copy the\r
    Corresponding Source from a network server at no charge.\r
\r
    c) Convey individual copies of the object code with a copy of the\r
    written offer to provide the Corresponding Source.  This\r
    alternative is allowed only occasionally and noncommercially, and\r
    only if you received the object code with such an offer, in accord\r
    with subsection 6b.\r
\r
    d) Convey the object code by offering access from a designated\r
    place (gratis or for a charge), and offer equivalent access to the\r
    Corresponding Source in the same way through the same place at no\r
    further charge.  You need not require recipients to copy the\r
    Corresponding Source along with the object code.  If the place to\r
    copy the object code is a network server, the Corresponding Source\r
    may be on a different server (operated by you or a third party)\r
    that supports equivalent copying facilities, provided you maintain\r
    clear directions next to the object code saying where to find the\r
    Corresponding Source.  Regardless of what server hosts the\r
    Corresponding Source, you remain obligated to ensure that it is\r
    available for as long as needed to satisfy these requirements.\r
\r
    e) Convey the object code using peer-to-peer transmission, provided\r
    you inform other peers where the object code and Corresponding\r
    Source of the work are being offered to the general public at no\r
    charge under subsection 6d.\r
\r
  A separable portion of the object code, whose source code is excluded\r
from the Corresponding Source as a System Library, need not be\r
included in conveying the object code work.\r
\r
  A "User Product" is either (1) a "consumer product", which means any\r
tangible personal property which is normally used for personal, family,\r
or household purposes, or (2) anything designed or sold for incorporation\r
into a dwelling.  In determining whether a product is a consumer product,\r
doubtful cases shall be resolved in favor of coverage.  For a particular\r
product received by a particular user, "normally used" refers to a\r
typical or common use of that class of product, regardless of the status\r
of the particular user or of the way in which the particular user\r
actually uses, or expects or is expected to use, the product.  A product\r
is a consumer product regardless of whether the product has substantial\r
commercial, industrial or non-consumer uses, unless such uses represent\r
the only significant mode of use of the product.\r
\r
  "Installation Information" for a User Product means any methods,\r
procedures, authorization keys, or other information required to install\r
and execute modified versions of a covered work in that User Product from\r
a modified version of its Corresponding Source.  The information must\r
suffice to ensure that the continued functioning of the modified object\r
code is in no case prevented or interfered with solely because\r
modification has been made.\r
\r
  If you convey an object code work under this section in, or with, or\r
specifically for use in, a User Product, and the conveying occurs as\r
part of a transaction in which the right of possession and use of the\r
User Product is transferred to the recipient in perpetuity or for a\r
fixed term (regardless of how the transaction is characterized), the\r
Corresponding Source conveyed under this section must be accompanied\r
by the Installation Information.  But this requirement does not apply\r
if neither you nor any third party retains the ability to install\r
modified object code on the User Product (for example, the work has\r
been installed in ROM).\r
\r
  The requirement to provide Installation Information does not include a\r
requirement to continue to provide support service, warranty, or updates\r
for a work that has been modified or installed by the recipient, or for\r
the User Product in which it has been modified or installed.  Access to a\r
network may be denied when the modification itself materially and\r
adversely affects the operation of the network or violates the rules and\r
protocols for communication across the network.\r
\r
  Corresponding Source conveyed, and Installation Information provided,\r
in accord with this section must be in a format that is publicly\r
documented (and with an implementation available to the public in\r
source code form), and must require no special password or key for\r
unpacking, reading or copying.\r
\r
  7. Additional Terms.\r
\r
  "Additional permissions" are terms that supplement the terms of this\r
License by making exceptions from one or more of its conditions.\r
Additional permissions that are applicable to the entire Program shall\r
be treated as though they were included in this License, to the extent\r
that they are valid under applicable law.  If additional permissions\r
apply only to part of the Program, that part may be used separately\r
under those permissions, but the entire Program remains governed by\r
this License without regard to the additional permissions.\r
\r
  When you convey a copy of a covered work, you may at your option\r
remove any additional permissions from that copy, or from any part of\r
it.  (Additional permissions may be written to require their own\r
removal in certain cases when you modify the work.)  You may place\r
additional permissions on material, added by you to a covered work,\r
for which you have or can give appropriate copyright permission.\r
\r
  Notwithstanding any other provision of this License, for material you\r
add to a covered work, you may (if authorized by the copyright holders of\r
that material) supplement the terms of this License with terms:\r
\r
    a) Disclaiming warranty or limiting liability differently from the\r
    terms of sections 15 and 16 of this License; or\r
\r
    b) Requiring preservation of specified reasonable legal notices or\r
    author attributions in that material or in the Appropriate Legal\r
    Notices displayed by works containing it; or\r
\r
    c) Prohibiting misrepresentation of the origin of that material, or\r
    requiring that modified versions of such material be marked in\r
    reasonable ways as different from the original version; or\r
\r
    d) Limiting the use for publicity purposes of names of licensors or\r
    authors of the material; or\r
\r
    e) Declining to grant rights under trademark law for use of some\r
    trade names, trademarks, or service marks; or\r
\r
    f) Requiring indemnification of licensors and authors of that\r
    material by anyone who conveys the material (or modified versions of\r
    it) with contractual assumptions of liability to the recipient, for\r
    any liability that these contractual assumptions directly impose on\r
    those licensors and authors.\r
\r
  All other non-permissive additional terms are considered "further\r
restrictions" within the meaning of section 10.  If the Program as you\r
received it, or any part of it, contains a notice stating that it is\r
governed by this License along with a term that is a further\r
restriction, you may remove that term.  If a license document contains\r
a further restriction but permits relicensing or conveying under this\r
License, you may add to a covered work material governed by the terms\r
of that license document, provided that the further restriction does\r
not survive such relicensing or conveying.\r
\r
  If you add terms to a covered work in accord with this section, you\r
must place, in the relevant source files, a statement of the\r
additional terms that apply to those files, or a notice indicating\r
where to find the applicable terms.\r
\r
  Additional terms, permissive or non-permissive, may be stated in the\r
form of a separately written license, or stated as exceptions;\r
the above requirements apply either way.\r
\r
  8. Termination.\r
\r
  You may not propagate or modify a covered work except as expressly\r
provided under this License.  Any attempt otherwise to propagate or\r
modify it is void, and will automatically terminate your rights under\r
this License (including any patent licenses granted under the third\r
paragraph of section 11).\r
\r
  However, if you cease all violation of this License, then your\r
license from a particular copyright holder is reinstated (a)\r
provisionally, unless and until the copyright holder explicitly and\r
finally terminates your license, and (b) permanently, if the copyright\r
holder fails to notify you of the violation by some reasonable means\r
prior to 60 days after the cessation.\r
\r
  Moreover, your license from a particular copyright holder is\r
reinstated permanently if the copyright holder notifies you of the\r
violation by some reasonable means, this is the first time you have\r
received notice of violation of this License (for any work) from that\r
copyright holder, and you cure the violation prior to 30 days after\r
your receipt of the notice.\r
\r
  Termination of your rights under this section does not terminate the\r
licenses of parties who have received copies or rights from you under\r
this License.  If your rights have been terminated and not permanently\r
reinstated, you do not qualify to receive new licenses for the same\r
material under section 10.\r
\r
  9. Acceptance Not Required for Having Copies.\r
\r
  You are not required to accept this License in order to receive or\r
run a copy of the Program.  Ancillary propagation of a covered work\r
occurring solely as a consequence of using peer-to-peer transmission\r
to receive a copy likewise does not require acceptance.  However,\r
nothing other than this License grants you permission to propagate or\r
modify any covered work.  These actions infringe copyright if you do\r
not accept this License.  Therefore, by modifying or propagating a\r
covered work, you indicate your acceptance of this License to do so.\r
\r
  10. Automatic Licensing of Downstream Recipients.\r
\r
  Each time you convey a covered work, the recipient automatically\r
receives a license from the original licensors, to run, modify and\r
propagate that work, subject to this License.  You are not responsible\r
for enforcing compliance by third parties with this License.\r
\r
  An "entity transaction" is a transaction transferring control of an\r
organization, or substantially all assets of one, or subdividing an\r
organization, or merging organizations.  If propagation of a covered\r
work results from an entity transaction, each party to that\r
transaction who receives a copy of the work also receives whatever\r
licenses to the work the party's predecessor in interest had or could\r
give under the previous paragraph, plus a right to possession of the\r
Corresponding Source of the work from the predecessor in interest, if\r
the predecessor has it or can get it with reasonable efforts.\r
\r
  You may not impose any further restrictions on the exercise of the\r
rights granted or affirmed under this License.  For example, you may\r
not impose a license fee, royalty, or other charge for exercise of\r
rights granted under this License, and you may not initiate litigation\r
(including a cross-claim or counterclaim in a lawsuit) alleging that\r
any patent claim is infringed by making, using, selling, offering for\r
sale, or importing the Program or any portion of it.\r
\r
  11. Patents.\r
\r
  A "contributor" is a copyright holder who authorizes use under this\r
License of the Program or a work on which the Program is based.  The\r
work thus licensed is called the contributor's "contributor version".\r
\r
  A contributor's "essential patent claims" are all patent claims\r
owned or controlled by the contributor, whether already acquired or\r
hereafter acquired, that would be infringed by some manner, permitted\r
by this License, of making, using, or selling its contributor version,\r
but do not include claims that would be infringed only as a\r
consequence of further modification of the contributor version.  For\r
purposes of this definition, "control" includes the right to grant\r
patent sublicenses in a manner consistent with the requirements of\r
this License.\r
\r
  Each contributor grants you a non-exclusive, worldwide, royalty-free\r
patent license under the contributor's essential patent claims, to\r
make, use, sell, offer for sale, import and otherwise run, modify and\r
propagate the contents of its contributor version.\r
\r
  In the following three paragraphs, a "patent license" is any express\r
agreement or commitment, however denominated, not to enforce a patent\r
(such as an express permission to practice a patent or covenant not to\r
sue for patent infringement).  To "grant" such a patent license to a\r
party means to make such an agreement or commitment not to enforce a\r
patent against the party.\r
\r
  If you convey a covered work, knowingly relying on a patent license,\r
and the Corresponding Source of the work is not available for anyone\r
to copy, free of charge and under the terms of this License, through a\r
publicly available network server or other readily accessible means,\r
then you must either (1) cause the Corresponding Source to be so\r
available, or (2) arrange to deprive yourself of the benefit of the\r
patent license for this particular work, or (3) arrange, in a manner\r
consistent with the requirements of this License, to extend the patent\r
license to downstream recipients.  "Knowingly relying" means you have\r
actual knowledge that, but for the patent license, your conveying the\r
covered work in a country, or your recipient's use of the covered work\r
in a country, would infringe one or more identifiable patents in that\r
country that you have reason to believe are valid.\r
\r
  If, pursuant to or in connection with a single transaction or\r
arrangement, you convey, or propagate by procuring conveyance of, a\r
covered work, and grant a patent license to some of the parties\r
receiving the covered work authorizing them to use, propagate, modify\r
or convey a specific copy of the covered work, then the patent license\r
you grant is automatically extended to all recipients of the covered\r
work and works based on it.\r
\r
  A patent license is "discriminatory" if it does not include within\r
the scope of its coverage, prohibits the exercise of, or is\r
conditioned on the non-exercise of one or more of the rights that are\r
specifically granted under this License.  You may not convey a covered\r
work if you are a party to an arrangement with a third party that is\r
in the business of distributing software, under which you make payment\r
to the third party based on the extent of your activity of conveying\r
the work, and under which the third party grants, to any of the\r
parties who would receive the covered work from you, a discriminatory\r
patent license (a) in connection with copies of the covered work\r
conveyed by you (or copies made from those copies), or (b) primarily\r
for and in connection with specific products or compilations that\r
contain the covered work, unless you entered into that arrangement,\r
or that patent license was granted, prior to 28 March 2007.\r
\r
  Nothing in this License shall be construed as excluding or limiting\r
any implied license or other defenses to infringement that may\r
otherwise be available to you under applicable patent law.\r
\r
  12. No Surrender of Others' Freedom.\r
\r
  If conditions are imposed on you (whether by court order, agreement or\r
otherwise) that contradict the conditions of this License, they do not\r
excuse you from the conditions of this License.  If you cannot convey a\r
covered work so as to satisfy simultaneously your obligations under this\r
License and any other pertinent obligations, then as a consequence you may\r
not convey it at all.  For example, if you agree to terms that obligate you\r
to collect a royalty for further conveying from those to whom you convey\r
the Program, the only way you could satisfy both those terms and this\r
License would be to refrain entirely from conveying the Program.\r
\r
  13. Remote Network Interaction; Use with the GNU General Public License.\r
\r
  Notwithstanding any other provision of this License, if you modify the\r
Program, your modified version must prominently offer all users\r
interacting with it remotely through a computer network (if your version\r
supports such interaction) an opportunity to receive the Corresponding\r
Source of your version by providing access to the Corresponding Source\r
from a network server at no charge, through some standard or customary\r
means of facilitating copying of software.  This Corresponding Source\r
shall include the Corresponding Source for any work covered by version 3\r
of the GNU General Public License that is incorporated pursuant to the\r
following paragraph.\r
\r
  Notwithstanding any other provision of this License, you have\r
permission to link or combine any covered work with a work licensed\r
under version 3 of the GNU General Public License into a single\r
combined work, and to convey the resulting work.  The terms of this\r
License will continue to apply to the part which is the covered work,\r
but the work with which it is combined will remain governed by version\r
3 of the GNU General Public License.\r
\r
  14. Revised Versions of this License.\r
\r
  The Free Software Foundation may publish revised and/or new versions of\r
the GNU Affero General Public License from time to time.  Such new versions\r
will be similar in spirit to the present version, but may differ in detail to\r
address new problems or concerns.\r
\r
  Each version is given a distinguishing version number.  If the\r
Program specifies that a certain numbered version of the GNU Affero General\r
Public License "or any later version" applies to it, you have the\r
option of following the terms and conditions either of that numbered\r
version or of any later version published by the Free Software\r
Foundation.  If the Program does not specify a version number of the\r
GNU Affero General Public License, you may choose any version ever published\r
by the Free Software Foundation.\r
\r
  If the Program specifies that a proxy can decide which future\r
versions of the GNU Affero General Public License can be used, that proxy's\r
public statement of acceptance of a version permanently authorizes you\r
to choose that version for the Program.\r
\r
  Later license versions may give you additional or different\r
permissions.  However, no additional obligations are imposed on any\r
author or copyright holder as a result of your choosing to follow a\r
later version.\r
\r
  15. Disclaimer of Warranty.\r
\r
  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY\r
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT\r
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY\r
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,\r
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR\r
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM\r
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF\r
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\r
\r
  16. Limitation of Liability.\r
\r
  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING\r
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS\r
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY\r
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE\r
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF\r
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD\r
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),\r
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF\r
SUCH DAMAGES.\r
\r
  17. Interpretation of Sections 15 and 16.\r
\r
  If the disclaimer of warranty and limitation of liability provided\r
above cannot be given local legal effect according to their terms,\r
reviewing courts shall apply local law that most closely approximates\r
an absolute waiver of all civil liability in connection with the\r
Program, unless a warranty or assumption of liability accompanies a\r
copy of the Program in return for a fee.\r
\r
                     END OF TERMS AND CONDITIONS\r
\r
            How to Apply These Terms to Your New Programs\r
\r
  If you develop a new program, and you want it to be of the greatest\r
possible use to the public, the best way to achieve this is to make it\r
free software which everyone can redistribute and change under these terms.\r
\r
  To do so, attach the following notices to the program.  It is safest\r
to attach them to the start of each source file to most effectively\r
state the exclusion of warranty; and each file should have at least\r
the "copyright" line and a pointer to where the full notice is found.\r
\r
    <one line to give the program's name and a brief idea of what it does.>\r
    Copyright (C) <year>  <name of author>\r
\r
    This program is free software: you can redistribute it and/or modify\r
    it under the terms of the GNU Affero General Public License as published by\r
    the Free Software Foundation, either version 3 of the License, or\r
    (at your option) any later version.\r
\r
    This program is distributed in the hope that it will be useful,\r
    but WITHOUT ANY WARRANTY; without even the implied warranty of\r
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\r
    GNU Affero General Public License for more details.\r
\r
    You should have received a copy of the GNU Affero General Public License\r
    along with this program.  If not, see <https://www.gnu.org/licenses/>.\r
\r
Also add information on how to contact you by electronic and paper mail.\r
\r
  If your software can interact with users remotely through a computer\r
network, you should also make sure that it provides a way for users to\r
get its source.  For example, if your program is a web application, its\r
interface could display a "Source" link that leads users to an archive\r
of the code.  There are many ways you could offer source, and different\r
solutions will be better for different programs; see section 13 for the\r
specific requirements.\r
\r
  You should also get your employer (if you work as a programmer) or school,\r
if any, to sign a "copyright disclaimer" for the program, if necessary.\r
For more information on this, and how to apply and follow the GNU AGPL, see\r
<https://www.gnu.org/licenses/>.\r
`, "type": "text/plain; charset=utf-8" }, "/": { "body": '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DSH Go \u5206\u4EAB\u4E0E\u7EDF\u8BA1</title><main><h1>DSH Go \u5206\u4EAB\u4E0E\u7EDF\u8BA1</h1><p>\u5206\u4EAB\u5185\u5BB9\u5728\u624B\u673A\u7AEF\u52A0\u5BC6\uFF0C\u6301\u6709\u5B8C\u6574\u94FE\u63A5\u7684\u4EBA\u53EF\u4EE5\u67E5\u770B\u3002</p><p>\u4F7F\u7528\u7EDF\u8BA1\u7531\u4F7F\u7528\u8005\u4E3B\u52A8\u5F00\u542F\uFF0C\u670D\u52A1\u4EC5\u63A5\u6536\u4F7F\u7528\u6B21\u6570\u548C\u8BBE\u5907\u6982\u8981\u3002</p><a href="https://github.com/zheyuanAI/dsh-Go/releases/latest">\u4E0B\u8F7D DSH Go</a><p><a href="https://github.com/zheyuanAI/dsh-Go/tree/local/services/share-worker">\u6E90\u7801 \xB7 AGPL-3.0</a> \xB7 <a href="/license">\u8BB8\u53EF\u5168\u6587</a></p></main></html>', "type": "text/html; charset=utf-8" } };

// services/share-worker/src/sites.ts
async function allow(env, client, scope, seconds, limit) {
  const slot = Math.floor(Date.now() / (seconds * 1e3));
  const hash = await hmacHex(env.USAGE_SECRET, `${scope}:${slot}:${client}`, 16);
  const key = `quota/${scope}/${slot}/${hash}`;
  for (let attempt = 0; attempt < 4; attempt++) {
    const old = await env.BUCKET.get(key);
    const count = old ? Number(await old.text()) : 0;
    if (!Number.isFinite(count) || count >= limit) return false;
    const stored = await env.BUCKET.put(key, String(count + 1), {
      onlyIf: old ? { etagMatches: old.etag } : { etagDoesNotMatch: "*" },
      customMetadata: { expiresAt: String((slot + 1) * seconds * 1e3) }
    });
    if (stored) return true;
  }
  return false;
}
async function sweep(env) {
  const now = Date.now();
  for (const prefix of ["7d/", "30d/", "usage/", "quota/"]) {
    const list = await env.BUCKET.list({ prefix, limit: 100, include: ["customMetadata"] });
    const expired = list.objects.filter((object) => {
      if (prefix === "7d/" || prefix === "30d/") {
        return object.uploaded.getTime() + (prefix === "7d/" ? 7 : 30) * 864e5 <= now;
      }
      return Number(object.customMetadata?.expiresAt ?? Infinity) <= now;
    });
    if (expired.length) await env.BUCKET.delete(expired.map((object) => object.key));
  }
}
async function collectUsage(request, env) {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (!await allow(env, clientKey(request), "usage", 60, 20)) return json(429, { error: "rate_limited" });
  if (!/^application\/json\s*(;|$)/i.test(request.headers.get("Content-Type") ?? "")) {
    return json(415, { error: "unsupported_media_type" });
  }
  const bytes = await readCapped(request, 2048);
  if (!bytes) return json(413, { error: "too_large" });
  let report;
  try {
    report = validateReport(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)));
  } catch {
    return json(400, { error: "bad_report" });
  }
  const { iid, ...fields } = report;
  const device = await hmacHex(env.USAGE_SECRET, `iid
${iid}`, 16);
  await env.BUCKET.put(`usage/${report.day}/${device}.json`, JSON.stringify({ ...fields, device }), {
    customMetadata: { expiresAt: String(Date.parse(`${report.day}T00:00:00Z`) + 31 * 864e5) }
  });
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}
async function route(request, env, ctx) {
  const path = new URL(request.url).pathname;
  if (!env.BUCKET || !env.USAGE_SECRET) return json(503, { error: "service_unavailable" });
  if (path === "/api/health" && request.method === "GET") {
    await env.BUCKET.head("health");
    return json(200, { service: "dsh-go-services", v: 1, sharing: true, usage: true });
  }
  if (path.startsWith("/api/")) {
    ctx.waitUntil(sweep(env).catch(() => {
    }));
    if (path === "/api/usage/v1") return collectUsage(request, env);
    const apiEnv = { ...env, MAX_BYTES: String(20 * 1024 * 1024) };
    if (path === "/api/v1/c" && request.method === "POST") {
      const client = clientKey(request);
      if (!await allow(env, client, "upload-minute", 60, 5) || !await allow(env, client, "upload-hour", 3600, 20)) {
        return json(429, { error: "rate_limited" }, { "Retry-After": "60" });
      }
      return upload(request, apiEnv);
    }
    const match = /^\/api\/v1\/c\/([0-9A-Za-z]{10})$/.exec(path);
    if (match) {
      if (!await allow(env, clientKey(request), "read", 60, 120)) return json(429, { error: "rate_limited" });
      if (request.method === "GET") return fetchBlob(request, apiEnv, match[1]);
      if (request.method === "DELETE") return remove(request, apiEnv, match[1]);
      return json(405, { error: "method_not_allowed" });
    }
    return json(404, { error: "not_found" });
  }
  if (request.method !== "GET" && request.method !== "HEAD") return json(405, { error: "method_not_allowed" });
  const assetPath = /^\/c\/[0-9A-Za-z]{10}\/?$/.test(path) ? "/c.html" : path === "/share" ? "/share/" : path;
  const asset = assets_default[assetPath];
  if (!asset) return json(404, { error: "not_found" });
  return new Response(request.method === "HEAD" ? null : asset.body, {
    headers: {
      "Content-Type": asset.type,
      "Cache-Control": "no-cache",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-Robots-Tag": "noindex"
    }
  });
}
var sites_default = {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch {
      return json(503, { error: "service_unavailable" });
    }
  }
};
export {
  sites_default as default
};
