/**
 * Canonical JSON: deterministic serialization + a strict, defensive parser.
 *
 * Why this exists
 * ---------------
 * Every signed structure in this system is signed over its *canonical byte
 * encoding*.  If two different byte strings could decode to the same logical
 * object (or two different objects could serialize to the same bytes), an
 * attacker who can influence the wire format could slip a field past the
 * verifier's semantic check.  We therefore enforce:
 *
 *   - one and only one serialization per value (JCS-style: keys sorted by
 *     UTF-16 code units, no insignificant whitespace, shortest number form),
 *   - a parser that rejects duplicate keys, prototype-polluting keys,
 *     non-canonical numbers, lone surrogates, and nesting/size beyond policy,
 *   - re-serialization check: parse(x) must canonicalize back to exactly x.
 *     A message that does not round-trip byte-for-byte is rejected.  This is
 *     what kills "two representations, one signature" attacks.
 *
 * Supported types are intentionally small: null, boolean, string, finite
 * number (safe integers only — we never sign floats), array, plain object.
 * Anything else (undefined, NaN, bigint, Date, Map, class instances, sparse
 * arrays, extra properties on arrays) is an error.
 */

import { fail } from "./errors.ts";

const MAX_DEPTH = 32;

/** Serialize a value to canonical JSON bytes. */
export function canonicalize(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalString(value));
}

export function canonicalString(value: unknown): string {
  const out: string[] = [];
  writeValue(value, out, 0);
  return out.join("");
}

function writeValue(v: unknown, out: string[], depth: number): void {
  if (depth > MAX_DEPTH) fail("CANONICALIZATION_ERROR", "canonical json: nesting too deep");
  if (v === null) {
    out.push("null");
    return;
  }
  switch (typeof v) {
    case "boolean":
      out.push(v ? "true" : "false");
      return;
    case "string":
      out.push(quote(v));
      return;
    case "number": {
      if (!Number.isSafeInteger(v)) {
        fail("CANONICALIZATION_ERROR", "canonical json: only safe integers are allowed");
      }
      if (Object.is(v, -0)) {
        out.push("0");
      } else {
        out.push(String(v));
      }
      return;
    }
    case "object": {
      if (Array.isArray(v)) {
        writeArray(v, out, depth);
        return;
      }
      writeObject(v as Record<string, unknown>, out, depth);
      return;
    }
    default:
      fail("CANONICALIZATION_ERROR", `canonical json: unsupported type ${typeof v}`);
  }
}

function writeArray(arr: ReadonlyArray<unknown>, out: string[], depth: number): void {
  // Reject sparse arrays and arrays with extra own (non-index) properties —
  // both would serialize to something that silently drops data.
  for (let i = 0; i < arr.length; i++) {
    if (!(i in arr)) fail("CANONICALIZATION_ERROR", "canonical json: sparse array");
  }
  for (const k of Object.keys(arr)) {
    if (!/^(0|[1-9][0-9]*)$/.test(k)) {
      fail("CANONICALIZATION_ERROR", "canonical json: array has non-index property");
    }
  }
  out.push("[");
  for (let i = 0; i < arr.length; i++) {
    if (i > 0) out.push(",");
    writeValue(arr[i], out, depth + 1);
  }
  out.push("]");
}

function writeObject(obj: Record<string, unknown>, out: string[], depth: number): void {
  const proto = Object.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) {
    fail("CANONICALIZATION_ERROR", "canonical json: not a plain object");
  }
  const keys = Object.keys(obj).sort(compareUtf16);
  out.push("{");
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]!;
    const val = obj[k];
    if (val === undefined) fail("CANONICALIZATION_ERROR", "canonical json: undefined value");
    if (i > 0) out.push(",");
    out.push(quote(k), ":");
    writeValue(val, out, depth + 1);
  }
  out.push("}");
}

/** RFC 8785 sorts object keys by UTF-16 code units of the raw string. */
function compareUtf16(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function quote(s: string): string {
  let r = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) {
      r += '\\"';
    } else if (c === 0x5c) {
      r += "\\\\";
    } else if (c < 0x20) {
      switch (c) {
        case 0x08: r += "\\b"; break;
        case 0x09: r += "\\t"; break;
        case 0x0a: r += "\\n"; break;
        case 0x0c: r += "\\f"; break;
        case 0x0d: r += "\\r"; break;
        default: r += "\\u" + c.toString(16).padStart(4, "0");
      }
    } else if (c >= 0xd800 && c <= 0xdbff) {
      // High surrogate: must be followed by a low surrogate.
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) fail("CANONICALIZATION_ERROR", "canonical json: lone surrogate");
      // Emit both code units verbatim (the pair is a valid astral char).
      r += s[i]! + s[i + 1]!;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      fail("CANONICALIZATION_ERROR", "canonical json: lone surrogate");
    } else {
      r += s[i]!;
    }
  }
  return r + '"';
}

// ---------------------------------------------------------------------------
// Strict parser
// ---------------------------------------------------------------------------

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export interface ParseLimits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly maxKeys: number;
}

const DEFAULT_LIMITS: ParseLimits = { maxBytes: 1 << 20, maxDepth: MAX_DEPTH, maxKeys: 4096 };

/**
 * Parse untrusted bytes into a value and verify the canonical round-trip.
 * Rejects:
 *  - malformed JSON / trailing garbage,
 *  - duplicate object keys,
 *  - `__proto__` / `constructor` / `prototype` keys,
 *  - numbers that are not safe integers or have non-canonical form (e.g. `1.0`, `1e3`),
 *  - lone surrogates in strings,
 *  - input whose canonical re-serialization differs from the original bytes.
 */
export function parseCanonical(input: Uint8Array, limits: ParseLimits = DEFAULT_LIMITS): unknown {
  if (input.length > limits.maxBytes) fail("MALFORMED_MESSAGE", "message exceeds size limit");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    fail("MALFORMED_MESSAGE", "message is not valid UTF-8");
  }
  const value = new StrictParser(text, limits).parse();
  // Byte-for-byte canonical round-trip.
  const again = canonicalString(value);
  if (again !== text) {
    fail("CANONICALIZATION_ERROR", "message encoding is not canonical");
  }
  return value;
}

class StrictParser {
  private i = 0;
  private keyCount = 0;
  private readonly s: string;
  private readonly limits: ParseLimits;
  constructor(s: string, limits: ParseLimits) {
    this.s = s;
    this.limits = limits;
  }

  parse(): unknown {
    this.skipWs();
    const v = this.value(0);
    this.skipWs();
    if (this.i !== this.s.length) fail("MALFORMED_MESSAGE", "trailing data after JSON value");
    return v;
  }

  private skipWs(): void {
    // Canonical JSON has no whitespace at all, but a few places legally allow
    // it in RFC 8259.  We only permit it outside strings and rely on the
    // final round-trip check to reject any that is not canonical.
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private value(depth: number): unknown {
    if (depth > this.limits.maxDepth) fail("MALFORMED_MESSAGE", "json nesting too deep");
    if (this.i >= this.s.length) fail("MALFORMED_MESSAGE", "unexpected end of JSON");
    const c = this.s.charCodeAt(this.i);
    if (c === 0x7b /* { */) return this.object(depth);
    if (c === 0x5b /* [ */) return this.array(depth);
    if (c === 0x22 /* " */) return this.string();
    if (c === 0x74 /* t */) return this.literal("true", true);
    if (c === 0x66 /* f */) return this.literal("false", false);
    if (c === 0x6e /* n */) return this.literal("null", null);
    if (c === 0x2d /* - */ || (c >= 0x30 && c <= 0x39)) return this.number();
    fail("MALFORMED_MESSAGE", `unexpected character at offset ${this.i}`);
  }

  private literal<T>(word: string, v: T): T {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    fail("MALFORMED_MESSAGE", `invalid literal at offset ${this.i}`);
  }

  private object(depth: number): Record<string, unknown> {
    this.i++; // {
    // Plain object with the default prototype is safe here because the parser
    // rejects `__proto__` / `constructor` / `prototype` keys *before* writing
    // them, so no assignment can reach the prototype chain.
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWs();
    if (this.s.charCodeAt(this.i) === 0x7d /* } */) {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      if (this.s.charCodeAt(this.i) !== 0x22) fail("MALFORMED_MESSAGE", "expected object key");
      const key = this.string();
      if (seen.has(key)) fail("MALFORMED_MESSAGE", `duplicate key: ${key}`);
      if (FORBIDDEN_KEYS.has(key)) fail("MALFORMED_MESSAGE", `forbidden key: ${key}`);
      seen.add(key);
      if (++this.keyCount > this.limits.maxKeys) fail("MALFORMED_MESSAGE", "too many keys");
      this.skipWs();
      if (this.s.charCodeAt(this.i) !== 0x3a /* : */) fail("MALFORMED_MESSAGE", "expected ':'");
      this.i++;
      this.skipWs();
      out[key] = this.value(depth + 1);
      this.skipWs();
      const c = this.s.charCodeAt(this.i);
      if (c === 0x2c /* , */) {
        this.i++;
        continue;
      }
      if (c === 0x7d /* } */) {
        this.i++;
        return out;
      }
      fail("MALFORMED_MESSAGE", "expected ',' or '}'");
    }
  }

  private array(depth: number): unknown[] {
    this.i++; // [
    const out: unknown[] = [];
    this.skipWs();
    if (this.s.charCodeAt(this.i) === 0x5d /* ] */) {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      out.push(this.value(depth + 1));
      this.skipWs();
      const c = this.s.charCodeAt(this.i);
      if (c === 0x2c /* , */) {
        this.i++;
        continue;
      }
      if (c === 0x5d /* ] */) {
        this.i++;
        return out;
      }
      fail("MALFORMED_MESSAGE", "expected ',' or ']'");
    }
  }

  private string(): string {
    this.i++; // opening quote
    let r = "";
    for (;;) {
      if (this.i >= this.s.length) fail("MALFORMED_MESSAGE", "unterminated string");
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22 /* " */) {
        this.i++;
        return r;
      }
      if (c === 0x5c /* \ */) {
        this.i++;
        const e = this.s.charCodeAt(this.i);
        switch (e) {
          case 0x22: r += '"'; this.i++; break;
          case 0x5c: r += "\\"; this.i++; break;
          case 0x2f: r += "/"; this.i++; break;
          case 0x62: r += "\b"; this.i++; break;
          case 0x66: r += "\f"; this.i++; break;
          case 0x6e: r += "\n"; this.i++; break;
          case 0x72: r += "\r"; this.i++; break;
          case 0x74: r += "\t"; this.i++; break;
          case 0x75: {
            this.i++;
            const hex = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("MALFORMED_MESSAGE", "bad \\u escape");
            r += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default: fail("MALFORMED_MESSAGE", "bad escape sequence");
        }
        continue;
      }
      if (c < 0x20) fail("MALFORMED_MESSAGE", "raw control character in string");
      r += this.s[this.i]!;
      this.i++;
    }
  }

  private number(): number {
    const start = this.i;
    if (this.s.charCodeAt(this.i) === 0x2d) this.i++;
    if (this.s.charCodeAt(this.i) === 0x30) {
      this.i++;
    } else if (this.s.charCodeAt(this.i) >= 0x31 && this.s.charCodeAt(this.i) <= 0x39) {
      while (this.i < this.s.length) {
        const c = this.s.charCodeAt(this.i);
        if (c >= 0x30 && c <= 0x39) this.i++;
        else break;
      }
    } else {
      fail("MALFORMED_MESSAGE", "invalid number");
    }
    // Any fraction/exponent makes it non-integer; we reject those outright
    // because canonical JSON here only admits integers.
    const c = this.s.charCodeAt(this.i);
    if (c === 0x2e /* . */ || c === 0x65 /* e */ || c === 0x45 /* E */) {
      fail("FIELD_OUT_OF_RANGE", "floating-point numbers are not permitted");
    }
    const n = Number(this.s.slice(start, this.i));
    if (!Number.isSafeInteger(n)) fail("FIELD_OUT_OF_RANGE", "integer out of safe range");
    return n;
  }
}

// ---------------------------------------------------------------------------
// Typed field readers — used by every message parser so structural checks
// live in exactly one place.
// ---------------------------------------------------------------------------

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function asObject(v: unknown, what: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("MALFORMED_MESSAGE", `${what}: expected object`);
  return v as Record<string, unknown>;
}

export function asArray(v: unknown, what: string): unknown[] {
  if (!Array.isArray(v)) fail("MALFORMED_MESSAGE", `${what}: expected array`);
  return v;
}

export function asString(v: unknown, what: string, maxLen = 4096): string {
  if (typeof v !== "string") fail("MALFORMED_MESSAGE", `${what}: expected string`);
  if (v.length > maxLen) fail("FIELD_OUT_OF_RANGE", `${what}: string too long`);
  return v;
}

export function asInt(v: unknown, what: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v)) fail("MALFORMED_MESSAGE", `${what}: expected integer`);
  if (v < min || v > max) fail("FIELD_OUT_OF_RANGE", `${what}: out of range`);
  return v;
}

export function asBool(v: unknown, what: string): boolean {
  if (typeof v !== "boolean") fail("MALFORMED_MESSAGE", `${what}: expected boolean`);
  return v;
}

/** Read a field that MUST be present (missing vs. null distinguished). */
export function req(obj: Record<string, unknown>, key: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) fail("MALFORMED_MESSAGE", `missing field: ${key}`);
  return obj[key];
}

/** Read an optional field; returns undefined only when the key is absent. */
export function opt(obj: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** Reject any object that carries keys outside the allowed set.  This stops
 *  an attacker from smuggling additional signed-but-uninterpreted fields that
 *  a different component might act on. */
export function onlyKeys(obj: Record<string, unknown>, allowed: ReadonlyArray<string>, what: string): void {
  const set = new Set(allowed);
  for (const k of Object.keys(obj)) {
    if (!set.has(k)) fail("MALFORMED_MESSAGE", `${what}: unexpected field '${k}'`);
  }
}
