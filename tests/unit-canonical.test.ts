import test from "node:test";
import assert from "node:assert/strict";

import { canonicalString, parseCanonical } from "../src/util/canonical.ts";
import { b64u, b64uDecode, ctEqual, fromHex, toHex } from "../src/util/bytes.ts";

test("canonical.json: sorts keys and is stable", () => {
  const a = canonicalString({ b: 1, a: 2, c: [3, 1, 2] });
  assert.equal(a, '{"a":2,"b":1,"c":[3,1,2]}');
});

test("canonical.json: rejects floats", () => {
  assert.throws(() => canonicalString({ x: 1.5 }), /integers/);
});

test("canonical.json: rejects undefined, bigint, sparse", () => {
  assert.throws(() => canonicalString({ x: undefined }));
  assert.throws(() => canonicalString({ x: 10n }));
  // eslint-disable-next-line no-sparse-arrays
  assert.throws(() => canonicalString([1, , 3]));
});

test("canonical.json: -0 canonicalizes to 0", () => {
  assert.equal(canonicalString(-0), "0");
});

test("parseCanonical: round-trips canonical bytes", () => {
  const text = '{"a":[1,2,3],"b":"x"}';
  const v = parseCanonical(new TextEncoder().encode(text));
  assert.deepEqual(v, { a: [1, 2, 3], b: "x" });
});

test("parseCanonical: rejects duplicate keys", () => {
  const text = '{"a":1,"a":2}';
  assert.throws(() => parseCanonical(new TextEncoder().encode(text)), /duplicate/);
});

test("parseCanonical: rejects non-canonical whitespace", () => {
  const text = '{ "a" : 1 }';
  assert.throws(() => parseCanonical(new TextEncoder().encode(text)), /canonical/);
});

test("parseCanonical: rejects prototype pollution keys", () => {
  const text = '{"__proto__":{"x":1}}';
  assert.throws(() => parseCanonical(new TextEncoder().encode(text)), /forbidden/);
});

test("parseCanonical: rejects floats and exponents", () => {
  assert.throws(() => parseCanonical(new TextEncoder().encode('{"a":1.0}')), /floating-point/);
  assert.throws(() => parseCanonical(new TextEncoder().encode('{"a":1e3}')), /floating-point/);
});

test("parseCanonical: rejects keys out of sorted order (non-canonical)", () => {
  const text = '{"b":1,"a":2}';
  assert.throws(() => parseCanonical(new TextEncoder().encode(text)), /canonical/);
});

test("base64url: canonical round-trip and rejects non-canonical", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const enc = b64u(bytes);
  assert.deepEqual([...b64uDecode(enc)], [...bytes]);
  // Padded form must be rejected.
  assert.throws(() => b64uDecode(enc + "=="), /alphabet/);
});

test("base64url: rejects non-canonical trailing bits", () => {
  // "QQ" decodes to the single byte 0x41; "QR" is non-canonical for 0x41.
  assert.deepEqual([...b64uDecode("QQ")], [0x41]);
  assert.throws(() => b64uDecode("QR"), /non-canonical/);
});

test("bytes: hex round-trip", () => {
  const b = new Uint8Array([0, 15, 16, 255]);
  assert.equal(toHex(b), "000f10ff");
  assert.deepEqual([...fromHex("000f10ff")], [0, 15, 16, 255]);
});

test("bytes: ctEqual", () => {
  assert.ok(ctEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
  assert.ok(!ctEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
  assert.ok(!ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])));
});
