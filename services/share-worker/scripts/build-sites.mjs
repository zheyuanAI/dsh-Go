// Bundle the Sites Worker and existing encrypted viewer into one ESM artifact.
import { build } from 'esbuild';
import { readFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../..');
const output = process.argv[2];
if (!output) throw Error('Pass an output Worker path');
const files = [
  ['/c.html', 'c.html', 'text/html; charset=utf-8'],
  ['/share/', 'index.html', 'text/html; charset=utf-8'],
  ['/share/share.js', 'share.js', 'text/javascript; charset=utf-8'],
  ['/share/viewer.js', 'viewer.js', 'text/javascript; charset=utf-8'],
  ['/share/viewer.css', 'viewer.css', 'text/css; charset=utf-8'],
  ['/share/favicon.svg', 'favicon.svg', 'image/svg+xml'],
];
const assets = Object.fromEntries(files.map(([path, file, type]) => [path, {
  body: readFileSync(resolve(repo, 'site/build/share', file), 'utf8')
    .replaceAll('ccch1mneyyy/dsh-go', 'zheyuanAI/dsh-Go'),
  type,
}]));
// The viewer's inline script changes when its download link moves to the fork.
const script = /<script>([\s\S]*?)<\/script>/.exec(assets['/c.html'].body)?.[1];
if (!script) throw Error('Hosted viewer script missing');
const digest = createHash('sha256').update(script).digest('base64');
assets['/c.html'].body = assets['/c.html'].body.replace(/sha256-[A-Za-z0-9+/=]+/, `sha256-${digest}`);
const sourceLink = '<a href="https://github.com/zheyuanAI/dsh-Go/tree/local/services/share-worker">源码 · AGPL-3.0</a>';
assets['/c.html'].body = assets['/c.html'].body.replace('</body>', `<footer>${sourceLink}</footer></body>`);
assets['/license'] = { body: readFileSync(resolve(repo, 'LICENSE'), 'utf8'), type: 'text/plain; charset=utf-8' };
assets['/'] = { body: `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DSH Go 分享与统计</title><main><h1>DSH Go 分享与统计</h1><p>分享内容在手机端加密，持有完整链接的人可以查看。</p><p>使用统计由使用者主动开启，服务仅接收使用次数和设备概要。</p><a href="https://github.com/zheyuanAI/dsh-Go/releases/latest">下载 DSH Go</a><p>${sourceLink} · <a href="/license">许可全文</a></p></main></html>`, type: 'text/html; charset=utf-8' };
mkdirSync(dirname(resolve(output)), { recursive: true });
await build({
  entryPoints: [resolve(here, '../src/sites.ts')], outfile: resolve(output),
  bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
  plugins: [{ name: 'viewer-assets', setup(b) {
    b.onResolve({ filter: /^dshgo:site-assets$/ }, () => ({ path: 'assets', namespace: 'viewer' }));
    b.onLoad({ filter: /.*/, namespace: 'viewer' }, () => ({ contents: `export default ${JSON.stringify(assets)}`, loader: 'js' }));
  } }],
});
