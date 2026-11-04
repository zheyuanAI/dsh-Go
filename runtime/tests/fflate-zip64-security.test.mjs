// The office worker must resolve the fixed fflate, including any nested copy.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import test from 'node:test';

if (!process.env.DSH_PREFIX) throw new Error('Set DSH_PREFIX to an installed runtime prefix');
const require = createRequire(join(resolve(process.env.DSH_PREFIX), 'node_modules/@deepseek-ai/libreoffice-kit/lib/worker.js'));
const fflate = require.resolve('fflate');

test('office ZIP64 parser terminates on a missing extra field', () => {
  // Run malformed input in a bounded child: vulnerable versions loop forever.
  const script = `
    const assert = require('node:assert/strict');
    const { unzipSync } = require(process.argv[1]);
    const zip = Buffer.alloc(144);
    zip.writeUInt32LE(0x02014b50, 0);
    zip.writeUInt32LE(0xffffffff, 20);
    zip.writeUInt32LE(0x06064b50, 46);
    zip.writeUInt32LE(1, 46 + 32);
    zip.writeUInt32LE(0, 46 + 48);
    zip.writeUInt32LE(0x07064b50, 102);
    zip.writeUInt32LE(46, 102 + 8);
    zip.writeUInt32LE(0x06054b50, 122);
    zip.writeUInt16LE(0xffff, 122 + 8);
    zip.writeUInt32LE(0xffffffff, 122 + 16);
    assert.throws(() => unzipSync(zip));
  `;
  const result = spawnSync(process.execPath, ['-e', script, fflate], { timeout: 3000, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test('office dependency still extracts normal document ZIP entries', () => {
  const { zipSync, unzipSync, strToU8, strFromU8 } = require('fflate');
  const original = '<document>test-only content</document>';
  const zipped = zipSync({ 'word/document.xml': strToU8(original) });
  assert.equal(strFromU8(unzipSync(zipped)['word/document.xml']), original);
});
