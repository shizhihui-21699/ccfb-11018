/**
 * Low-level byte utilities.
 *
 * Everything here is dependency-free and portable across Node and the
 * Electron renderer (WebCrypto only).  We deliberately avoid Node's Buffer
 * in this layer so the modules can be reused unchanged by the desktop UI.
 */


/**
 * All byte buffers in this codebase are backed by a plain `ArrayBuffer`, never
 * a `SharedArrayBuffer`.  Naming that explicitly keeps us assignable to
 * WebCrypto's `BufferSource` without unsafe casts.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Encode(s: string): Bytes {
  return encoder.encode(s);
}

/** UTF-8 decode that throws on malformed sequences instead of substituting U+FFFD. */
export function utf8Decode(b: Bytes): string {
  return decoder.decode(b);
}

export function toHex(b: Bytes): string {
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(s: string): Bytes {
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexVal(s.charCodeAt(i * 2));
    const lo = hexVal(s.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) throw new Error("hex: invalid character");
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexVal(c: number): number {
  if (c >= 48 && c <= 57) return c - 48; // 0-9
  if (c >= 97 && c <= 102) return c - 87; // a-f
  if (c >= 65 && c <= 70) return c - 55; // A-F
  return -1;
}

/** Base64url without padding — the encoding used inside signed structures. */
export function b64u(bytes: Readonly<Uint8Array>): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function b64uDecode(s: string): Bytes {
  if (typeof s !== "string") throw new Error("b64u: not a string");
  // Reject padded / non-canonical input so two encodings can never decode to
  // the same bytes (which would let an attacker vary a signed field's text).
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("b64u: invalid alphabet");
  if (s.length % 4 === 1) throw new Error("b64u: invalid length");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    throw new Error("b64u: invalid base64");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // Reject non-canonical trailing bits (base64 allows multiple encodings of
  // the same bytes when length % 4 != 0).
  if (b64u(out) !== s) throw new Error("b64u: non-canonical encoding");
  return out;
}

export function concat(...parts: ReadonlyArray<Bytes>): Bytes {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time equality (no early return on differing bytes). */
export function ctEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function randomBytes(n: number): Bytes {
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("randomBytes: bad length");
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Best-effort wipe. JS cannot guarantee this (GC may copy), but it limits
 *  the window during which transient secrets sit in the heap. */
export function zeroize(...bufs: ReadonlyArray<Uint8Array>): void {
  for (const b of bufs) b.fill(0);
}

export function assertLen(b: Bytes, n: number, what: string): void {
  if (b.length !== n) throw new Error(`${what}: expected ${n} bytes, got ${b.length}`);
}

export function u32be(n: number): Bytes {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error("u32be: out of range");
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export function u64be(n: number): Bytes {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("u64be: out of range");
  const hi = Math.floor(n / 2 ** 32);
  const lo = n >>> 0;
  return concat(u32be(hi), u32be(lo));
}
