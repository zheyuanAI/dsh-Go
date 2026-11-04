// Oversize collections must be rejected before walking or allocating per element.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import test from 'node:test';

if (!process.env.DSH_PREFIX) throw new Error('Set DSH_PREFIX to an installed runtime prefix');
const require = createRequire(join(resolve(process.env.DSH_PREFIX), 'package.json'));
const { z } = require('zod');

for (const kind of ['array', 'set', 'map']) {
  test(`Zod ${kind} rejects excessive size before parsing any element`, () => {
    let parsed = 0;
    const element = z.number().transform(value => { parsed++; return value; });
    const values = Array.from({ length: 100 }, (_, i) => i);
    const schema = kind === 'array' ? z.array(element).max(2)
      : kind === 'set' ? z.set(element).max(2)
      : z.map(z.number(), element).max(2);
    const input = kind === 'array' ? values : kind === 'set' ? new Set(values)
      : new Map(values.map(value => [value, value]));
    const result = schema.safeParse(input);
    assert.equal(result.success, false);
    assert.equal(result.error.issues[0].code, 'too_big');
    assert.equal(parsed, 0, 'oversize input must not run element parsers');
    const small = kind === 'array' ? [1] : kind === 'set' ? new Set([1]) : new Map([[1, 1]]);
    assert.equal(schema.safeParse(small).success, true);
    assert.equal(parsed, 1, 'valid collections still parse normally');
  });
}
