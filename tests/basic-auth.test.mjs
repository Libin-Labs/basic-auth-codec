import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { encodeBasicCredentials, decodeBasicCredentials } from '../dist/esm/index.js';

test('encodes and decodes RFC 7617 UTF-8 credentials', () => {
  const header = encodeBasicCredentials('søren', 'páss');
  assert.equal(header, 'Basic c8O4cmVuOnDDoXNz');
  assert.deepEqual(decodeBasicCredentials(header), { username: 'søren', password: 'páss' });
});
test('splits credentials at the first colon so passwords may contain colons', () => {
  assert.deepEqual(decodeBasicCredentials(encodeBasicCredentials('user', 'a:b:c')), {
    username: 'user',
    password: 'a:b:c',
  });
});
test('scheme matching is case-insensitive and only the credential token is decoded', () => {
  assert.deepEqual(decodeBasicCredentials('basic dTpw'), { username: 'u', password: 'p' });
  assert.throws(() => decodeBasicCredentials('Basic dTpw extra'), TypeError);
});
test('rejects colons in usernames and forbidden controls', () => {
  assert.throws(() => encodeBasicCredentials('a:b', 'c'), TypeError);
  assert.throws(() => encodeBasicCredentials('a', 'b\nc'), TypeError);
  assert.throws(() => decodeBasicCredentials(encodeBasicCredentials('u', 'p') + '\r'), TypeError);
  assert.throws(() => decodeBasicCredentials('Basic dTpw\n'), TypeError);
  assert.throws(() => encodeBasicCredentials('\ud800', 'pass'), TypeError);
});
test('rejects invalid and noncanonical base64 and invalid UTF-8', () => {
  for (const token of ['dTpw!', 'dTpw=', '/w==', 'dTpw===='])
    assert.throws(() => decodeBasicCredentials(`Basic ${token}`), TypeError);
});
test('enforces input bounds and requires a separator colon', () => {
  assert.throws(() => decodeBasicCredentials(`Basic ${'A'.repeat(22_000)}`), TypeError);
  const base64 = Buffer.from('nocolon').toString('base64');
  assert.throws(() => decodeBasicCredentials(`Basic ${base64}`), TypeError);
});
test('CommonJS exposes browser-independent Basic codec functions', () => {
  const api = createRequire(import.meta.url)('../dist/cjs/index.js');
  assert.deepEqual(Object.keys(api).sort(), ['decodeBasicCredentials', 'encodeBasicCredentials']);
});
