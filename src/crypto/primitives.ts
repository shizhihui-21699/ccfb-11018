/**
 * Cryptographic primitives — WebCrypto only, no third-party dependencies.
 *
 * Algorithm choices (deliberately small and modern):
 *   - Ed25519  : signatures (certs, attestation statements, policy bundles)
 *   - X25519   : ephemeral session key agreement
 *   - HKDF-SHA256 : key derivation, always with a distinct domain `info`
 *   - HMAC-SHA256 : key confirmation & record MACs
 *   - AES-256-GCM : sealing at-rest state (trust store)
 *   - SHA-256  : every hash, always domain-separated
 *
 * Kerckhoffs's principle is central to this system: the attacker is assumed
 * to know every byte of this file and the full wire protocol.  Security rests
 * on possession of non-exportable private keys, never on algorithm secrecy.
 *
 * Key-handling discipline:
 *   - Host-side code (manager, attestation verifier) only ever imports PUBLIC
 *     keys (raw 32-byte form).  It never generates or holds device private
 *     keys.  `device/` (the simulator) is the only place private keys live.
 *   - Every signing key we create is non-extractable where the platform
 *     allows it.
 */

import { fail } from "../util/errors.ts";
import { assertLen, b64u, b64uDecode, concat, ctEqual, randomBytes, u32be, zeroize, type Bytes } from "../util/bytes.ts";
import { canonicalString } from "../util/canonical.ts";

const subtle = globalThis.crypto.subtle;

export const SHA256_LEN = 32;
export const SIG_LEN = 64;
export const X25519_LEN = 32;

// ---------------------------------------------------------------------------
// Hashes with domain separation
// ---------------------------------------------------------------------------

/**
 * Domain-separated, length-prefixed hash:
 *   SHA-256( u32(len(label)) || label || u32(len(p1)) || p1 || ... )
 *
 * Length prefixes make the encoding injective: `H("a","bc") != H("ab","c")`,
 * so an attacker cannot move bytes between fields of a signed structure.
 */
export async function domainHash(label: string, ...parts: ReadonlyArray<Bytes>): Promise<Bytes> {
  const labelBytes = new TextEncoder().encode(label);
  if (labelBytes.length === 0 || labelBytes.length > 128) fail("INTERNAL_ERROR", "domainHash: bad label");
  const chunks: Bytes[] = [u32be(labelBytes.length), labelBytes];
  for (const p of parts) chunks.push(u32be(p.length), p);
  return sha256(concat(...chunks));
}

export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

/** Hash a canonical-JSON-able value under a domain label. */
export async function digestOf(label: string, value: unknown): Promise<Bytes> {
  return domainHash(label, new TextEncoder().encode(canonicalString(value)));
}

// ---------------------------------------------------------------------------
// Ed25519 signatures
// ---------------------------------------------------------------------------

export interface Ed25519PublicKeyJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
}

export interface Ed25519PublicKey {
  readonly raw: Bytes;
  readonly jwk: Ed25519PublicKeyJwk;
  /** Stable base64url SHA-256 thumbprint (RFC 8032 raw key hashed). */
  readonly kid: string;
  /** WebCrypto handle, cached. */
  readonly key: CryptoKey;
}

const pubCache = new Map<string, Ed25519PublicKey>();

/** Import a raw 32-byte Ed25519 public key. */
export async function importEd25519Public(raw: Bytes): Promise<Ed25519PublicKey> {
  assertLen(raw, X25519_LEN, "ed25519 public key");
  const kid = b64u(await sha256(raw));
  const cached = pubCache.get(kid);
  if (cached) return cached;
  let key: CryptoKey;
  try {
    key = await subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
  } catch {
    fail("CERT_PARSE_ERROR", "invalid Ed25519 public key");
  }
  const obj: Ed25519PublicKey = {
    raw: raw.slice(),
    jwk: { kty: "OKP", crv: "Ed25519", x: b64u(raw) },
    kid,
    key,
  };
  pubCache.set(kid, obj);
  return obj;
}

export async function importEd25519PublicB64(x: string): Promise<Ed25519PublicKey> {
  let raw: Bytes;
  try {
    raw = b64uDecode(x);
  } catch {
    fail("CERT_PARSE_ERROR", "invalid Ed25519 public key encoding");
  }
  return importEd25519Public(raw);
}

/**
 * Verify a signature.  Returns boolean rather than throwing so callers can
 * choose the failure code; malformed inputs simply return false.
 */
export async function ed25519Verify(
  pub: Ed25519PublicKey,
  message: Bytes,
  signature: Bytes,
): Promise<boolean> {
  if (signature.length !== SIG_LEN) return false;
  try {
    return await subtle.verify({ name: "Ed25519" }, pub.key, signature, message);
  } catch {
    return false;
  }
}

/** An Ed25519 signing key.  Only the device simulator / factory tool holds
 *  these; the host application never has one for a real device. */
export interface Ed25519Signer {
  readonly public: Ed25519PublicKey;
  sign(message: Bytes): Promise<Bytes>;
}

export async function generateEd25519Signer(): Promise<Ed25519Signer> {
  const kp = await subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  const pub = await importEd25519Public(raw);
  return {
    public: pub,
    async sign(message: Bytes): Promise<Bytes> {
      return new Uint8Array(await subtle.sign({ name: "Ed25519" }, kp.privateKey, message));
    },
  };
}

/**
 * Import a pkcs8 Ed25519 private key (factory provisioning / simulator
 * persistence).  The imported key is non-extractable, so its public half
 * cannot be recovered from it; the caller must supply the raw public key.
 * We verify the pairing in `verifyEd25519Pair` so a mismatched pair can never
 * be used silently.
 */
export async function importEd25519SignerPkcs8(
  pkcs8: Bytes,
  rawPublic: Bytes,
): Promise<Ed25519Signer> {
  let priv: CryptoKey;
  let pub: Ed25519PublicKey;
  try {
    priv = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    pub = await importEd25519Public(rawPublic);
  } catch (e) {
    if (e instanceof Error && e.name === "AttestationError") throw e;
    fail("INTERNAL_ERROR", "invalid Ed25519 private key");
  }
  const signer: Ed25519Signer = {
    public: pub,
    async sign(message: Bytes): Promise<Bytes> {
      return new Uint8Array(await subtle.sign({ name: "Ed25519" }, priv, message));
    },
  };
  // Self-test: sign/verify one probe so an inconsistent pair fails loudly at
  // import time, not in the middle of a handshake.
  const probe = randomBytes(16);
  const sig = await signer.sign(probe);
  if (!(await ed25519Verify(pub, probe, sig))) {
    fail("INTERNAL_ERROR", "Ed25519 key pair does not match the supplied public key");
  }
  return signer;
}

/** Export an extractable private key's pkcs8 form (factory tool only). */
export async function exportEd25519Pkcs8(privateKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
}

// ---------------------------------------------------------------------------
// X25519 ephemeral key agreement
// ---------------------------------------------------------------------------

export interface X25519KeyPair {
  readonly privateKey: CryptoKey;
  readonly publicRaw: Bytes;
}

export async function generateX25519(): Promise<X25519KeyPair> {
  const kp = (await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicRaw };
}

/**
 * X25519 ECDH.  Rejects low-order public keys: WebCrypto implementations are
 * expected to do this, but we verify explicitly so a platform that does not
 * cannot silently hand us an all-zero shared secret.
 */
export async function x25519Derive(privateKey: CryptoKey, peerPublicRaw: Bytes): Promise<Bytes> {
  assertLen(peerPublicRaw, X25519_LEN, "x25519 peer public key");
  let peer: CryptoKey;
  try {
    peer = await subtle.importKey("raw", peerPublicRaw, { name: "X25519" }, true, []);
  } catch {
    fail("SESSION_KEY_UNCONFIRMED", "invalid peer X25519 public key");
  }
  let bits: ArrayBuffer;
  try {
    bits = await subtle.deriveBits({ name: "X25519", public: peer }, privateKey, 256);
  } catch {
    // Low-order point -> deriveBits throws in Node; treat as a protocol error.
    fail("SESSION_KEY_UNCONFIRMED", "X25519 key agreement failed (low-order public key)");
  }
  const shared = new Uint8Array(bits);
  if (shared.length !== 32) fail("INTERNAL_ERROR", "x25519: unexpected shared secret length");
  // Belt-and-braces all-zero rejection.
  let acc = 0;
  for (const b of shared) acc |= b;
  if (acc === 0) {
    zeroize(shared);
    fail("SESSION_KEY_UNCONFIRMED", "X25519 produced an all-zero shared secret");
  }
  return shared;
}

// ---------------------------------------------------------------------------
// HKDF / HMAC / AES-GCM
// ---------------------------------------------------------------------------

export async function hkdf(
  ikm: Bytes,
  salt: Bytes,
  info: string,
  length: number,
): Promise<Bytes> {
  if (length <= 0 || length > 255 * 32) fail("INTERNAL_ERROR", "hkdf: bad output length");
  const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacKey(key: Bytes): Promise<CryptoKey> {
  if (key.length < 16) fail("INTERNAL_ERROR", "hmac: key too short");
  return subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function hmacSign(key: CryptoKey, data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.sign({ name: "HMAC" }, key, data));
}

export async function hmacVerify(key: CryptoKey, data: Bytes, mac: Bytes): Promise<boolean> {
  try {
    return await subtle.verify({ name: "HMAC" }, key, mac, data);
  } catch {
    return false;
  }
}

/** Constant-time comparison wrapper for MAC values produced elsewhere. */
export function macEqual(a: Bytes, b: Bytes): boolean {
  return ctEqual(a, b);
}

export async function aesGcmSeal(
  key: Bytes,
  plaintext: Bytes,
  aad: Bytes,
): Promise<{ nonce: Bytes; ciphertext: Bytes }> {
  assertLen(key, 32, "aes-256-gcm key");
  const k = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, plaintext));
  return { nonce, ciphertext: ct };
}

export async function aesGcmOpen(
  key: Bytes,
  nonce: Bytes,
  ciphertext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  assertLen(key, 32, "aes-256-gcm key");
  assertLen(nonce, 12, "aes-256-gcm nonce");
  const k = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, ciphertext));
  } catch {
    fail("TRUST_STORE_SEAL_INVALID", "authenticated decryption failed");
  }
}

/** Derive a 32-byte AES key from a high-entropy secret. */
export async function deriveStorageKey(secret: Bytes, context: string): Promise<Bytes> {
  return hkdf(secret, new Uint8Array(32), `storage-key/v1/${context}`, 32);
}
