/**
 * Wire messages for the attestation handshake.
 *
 * Every message is canonical JSON over a bounded schema.  Parsing is strict
 * (unknown fields rejected) so a malicious device cannot smuggle extra fields
 * that a future code path might honour.  Byte fields are base64url.
 *
 * Handshake (4 flights):
 *
 *   Host  -> Dev : HELLO      { sessionId, hostNonce, hostEphPub }
 *   Dev   -> Host: ATTEST     { ..., certBundle, statement, statementSig }
 *   Host  -> Dev : CONFIRM    { transcriptHash, hostConfirm }
 *   Dev   -> Host: READY      { transcriptHash, deviceConfirm }
 *
 * Security properties this shape gives us:
 *   - Freshness: `hostNonce` is 32 random bytes generated per connection.  An
 *     attacker replaying a recorded ATTEST fails because the nonce differs.
 *   - Liveness / presence: the device must produce fresh signatures for THIS
 *     nonce (statementSig by the SE key; `challengeSig` by every component).
 *   - Channel binding: both ephemeral X25519 keys are inside the signed
 *     transcript, so signatures cannot be transplanted to another session.
 *   - Key confirmation: each side sends an HMAC under a key derived from the
 *     ECDH shared secret; a party that cannot compute it cannot finish.
 *   - Relay detection: if a middlebox re-keys the ECDH (the only way to read
 *     traffic), the SAS derived from the shared secret differs on each side.
 *     A transparent relay learns nothing, so it is not a confidentiality threat
 *     (documented in docs/threat-model.md).
 *
 * Secret-free by construction: no message has a field that could carry seed /
 * xprv / mnemonic material.  The only bytes the host ever receives are public
 * keys, signatures, hashes, counters, and identifiers.  See `assertNoSecrets`.
 */

import {
  asArray,
  asBool,
  asInt,
  asObject,
  asString,
  canonicalString,
  onlyKeys,
  parseCanonical,
  req,
} from "../util/canonical.ts";
import { fail } from "../util/errors.ts";
import { b64uDecode, type Bytes } from "../util/bytes.ts";

export const PROTOCOL_VERSION = 1;
export const NONCE_LEN = 32;
export const SESSION_ID_LEN = 16;
export const MAC_LEN = 32;

const KID_RE = /^[A-Za-z0-9_-]{43}$/;
const SERIAL_RE = /^[A-Z0-9][A-Z0-9-]{3,31}$/;
const MODEL_RE = /^[A-Z0-9][A-Z0-9-]{1,31}$/;
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?$/;

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

export function readBytes(v: unknown, what: string, expectedLen?: number): Bytes {
  const s = asString(v, what, 4096);
  let out: Bytes;
  try {
    out = b64uDecode(s);
  } catch {
    fail("MALFORMED_MESSAGE", `${what}: invalid base64url`);
  }
  if (expectedLen !== undefined && out.length !== expectedLen) {
    fail("MALFORMED_MESSAGE", `${what}: expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}

export function readKid(v: unknown, what: string): string {
  const s = asString(v, what, 64);
  if (!KID_RE.test(s)) fail("MALFORMED_MESSAGE", `${what}: invalid key id`);
  return s;
}

/** Read a raw Ed25519 public key (base64url, exactly 32 bytes). */
export function readPub(v: unknown, what: string): string {
  const s = asString(v, what, 64);
  readBytes(s, what, 32);
  return s;
}

export function readSerial(v: unknown, what: string): string {
  const s = asString(v, what, 32);
  if (!SERIAL_RE.test(s)) fail("MALFORMED_MESSAGE", `${what}: invalid serial`);
  return s;
}

export function readModel(v: unknown, what: string): string {
  const s = asString(v, what, 32);
  if (!MODEL_RE.test(s)) fail("MALFORMED_MESSAGE", `${what}: invalid model`);
  return s;
}

export function readVersion(v: unknown, what: string): string {
  const s = asString(v, what, 32);
  if (!VERSION_RE.test(s)) fail("MALFORMED_MESSAGE", `${what}: invalid version`);
  return s;
}

export function readTime(v: unknown, what: string): number {
  return asInt(v, what, 0, 4_102_444_800);
}

export function readU32(v: unknown, what: string): number {
  return asInt(v, what, 0, 0xffffffff);
}

// ---------------------------------------------------------------------------
// HELLO
// ---------------------------------------------------------------------------

const HELLO_FIELDS = ["v", "kind", "sessionId", "hostNonce", "hostEphPub", "hostTime"] as const;

export interface HelloMessage {
  readonly v: 1;
  readonly kind: "hello";
  readonly sessionId: string; // b64u(16)
  readonly hostNonce: string; // b64u(32)
  readonly hostEphPub: string; // b64u(32)
  readonly hostTime: number;
}

export function encodeHello(m: HelloMessage): Bytes {
  return new TextEncoder().encode(canonicalString(m));
}

export function parseHello(input: unknown): HelloMessage {
  const o = asObject(input, "hello");
  onlyKeys(o, HELLO_FIELDS, "hello");
  if (asInt(req(o, "v"), "hello.v", 1, 255) !== PROTOCOL_VERSION) {
    fail("PROTOCOL_VERSION_UNSUPPORTED", "unsupported protocol version");
  }
  if (asString(req(o, "kind"), "hello.kind", 8) !== "hello") fail("MALFORMED_MESSAGE", "hello: bad kind");
  readBytes(req(o, "sessionId"), "hello.sessionId", SESSION_ID_LEN);
  readBytes(req(o, "hostNonce"), "hello.hostNonce", NONCE_LEN);
  readBytes(req(o, "hostEphPub"), "hello.hostEphPub", 32);
  const hostTime = readTime(req(o, "hostTime"), "hello.hostTime");
  return {
    v: 1,
    kind: "hello",
    sessionId: asString(req(o, "sessionId"), "hello.sessionId"),
    hostNonce: asString(req(o, "hostNonce"), "hello.hostNonce"),
    hostEphPub: asString(req(o, "hostEphPub"), "hello.hostEphPub"),
    hostTime,
  };
}

// ---------------------------------------------------------------------------
// ATTEST
// ---------------------------------------------------------------------------

const ATTEST_FIELDS = ["v", "kind", "sessionId", "hostNonce", "deviceNonce", "deviceEphPub", "certBundle", "statement", "statementSig"] as const;

export interface AttestMessage {
  readonly v: 1;
  readonly kind: "attest";
  readonly sessionId: string;
  readonly hostNonce: string;
  readonly deviceNonce: string;
  readonly deviceEphPub: string;
  readonly certBundle: ReadonlyArray<unknown>;
  readonly statement: unknown;
  readonly statementSig: string;
}

export function encodeAttest(m: AttestMessage): Bytes {
  return new TextEncoder().encode(canonicalString(m));
}

export function parseAttest(input: unknown): AttestMessage {
  const o = asObject(input, "attest");
  onlyKeys(o, ATTEST_FIELDS, "attest");
  if (asInt(req(o, "v"), "attest.v", 1, 255) !== PROTOCOL_VERSION) {
    fail("PROTOCOL_VERSION_UNSUPPORTED", "unsupported protocol version");
  }
  if (asString(req(o, "kind"), "attest.kind", 8) !== "attest") fail("MALFORMED_MESSAGE", "attest: bad kind");
  readBytes(req(o, "sessionId"), "attest.sessionId", SESSION_ID_LEN);
  readBytes(req(o, "hostNonce"), "attest.hostNonce", NONCE_LEN);
  readBytes(req(o, "deviceNonce"), "attest.deviceNonce", NONCE_LEN);
  readBytes(req(o, "deviceEphPub"), "attest.deviceEphPub", 32);
  const certBundle = asArray(req(o, "certBundle"), "attest.certBundle");
  if (certBundle.length === 0 || certBundle.length > 8) fail("MALFORMED_MESSAGE", "attest: bad certBundle length");
  readBytes(req(o, "statementSig"), "attest.statementSig", 64);
  return {
    v: 1,
    kind: "attest",
    sessionId: asString(req(o, "sessionId"), "attest.sessionId"),
    hostNonce: asString(req(o, "hostNonce"), "attest.hostNonce"),
    deviceNonce: asString(req(o, "deviceNonce"), "attest.deviceNonce"),
    deviceEphPub: asString(req(o, "deviceEphPub"), "attest.deviceEphPub"),
    certBundle: certBundle.slice(),
    statement: req(o, "statement"),
    statementSig: asString(req(o, "statementSig"), "attest.statementSig"),
  };
}

// ---------------------------------------------------------------------------
// CONFIRM / READY
// ---------------------------------------------------------------------------

const CONFIRM_FIELDS = ["v", "kind", "sessionId", "transcriptHash", "hostConfirm"] as const;

export interface ConfirmMessage {
  readonly v: 1;
  readonly kind: "confirm";
  readonly sessionId: string;
  readonly transcriptHash: string;
  readonly hostConfirm: string;
}

export function encodeConfirm(m: ConfirmMessage): Bytes {
  return new TextEncoder().encode(canonicalString(m));
}

export function parseConfirm(input: unknown): ConfirmMessage {
  const o = asObject(input, "confirm");
  onlyKeys(o, CONFIRM_FIELDS, "confirm");
  if (asInt(req(o, "v"), "confirm.v", 1, 255) !== PROTOCOL_VERSION) {
    fail("PROTOCOL_VERSION_UNSUPPORTED", "unsupported protocol version");
  }
  if (asString(req(o, "kind"), "confirm.kind", 8) !== "confirm") fail("MALFORMED_MESSAGE", "confirm: bad kind");
  readBytes(req(o, "sessionId"), "confirm.sessionId", SESSION_ID_LEN);
  readBytes(req(o, "transcriptHash"), "confirm.transcriptHash", 32);
  readBytes(req(o, "hostConfirm"), "confirm.hostConfirm", MAC_LEN);
  return {
    v: 1,
    kind: "confirm",
    sessionId: asString(req(o, "sessionId"), "confirm.sessionId"),
    transcriptHash: asString(req(o, "transcriptHash"), "confirm.transcriptHash"),
    hostConfirm: asString(req(o, "hostConfirm"), "confirm.hostConfirm"),
  };
}

const READY_FIELDS = ["v", "kind", "sessionId", "transcriptHash", "deviceConfirm"] as const;

export interface ReadyMessage {
  readonly v: 1;
  readonly kind: "ready";
  readonly sessionId: string;
  readonly transcriptHash: string;
  readonly deviceConfirm: string;
}

export function encodeReady(m: ReadyMessage): Bytes {
  return new TextEncoder().encode(canonicalString(m));
}

export function parseReady(input: unknown): ReadyMessage {
  const o = asObject(input, "ready");
  onlyKeys(o, READY_FIELDS, "ready");
  if (asInt(req(o, "v"), "ready.v", 1, 255) !== PROTOCOL_VERSION) {
    fail("PROTOCOL_VERSION_UNSUPPORTED", "unsupported protocol version");
  }
  if (asString(req(o, "kind"), "ready.kind", 8) !== "ready") fail("MALFORMED_MESSAGE", "ready: bad kind");
  readBytes(req(o, "sessionId"), "ready.sessionId", SESSION_ID_LEN);
  readBytes(req(o, "transcriptHash"), "ready.transcriptHash", 32);
  readBytes(req(o, "deviceConfirm"), "ready.deviceConfirm", MAC_LEN);
  return {
    v: 1,
    kind: "ready",
    sessionId: asString(req(o, "sessionId"), "ready.sessionId"),
    transcriptHash: asString(req(o, "transcriptHash"), "ready.transcriptHash"),
    deviceConfirm: asString(req(o, "deviceConfirm"), "ready.deviceConfirm"),
  };
}

// ---------------------------------------------------------------------------
// Wire framing + secret-leak guard
// ---------------------------------------------------------------------------

const MAX_MESSAGE_BYTES = 1 << 20;

/** Decode one framed message from raw bytes into an `unknown` JSON value. */
export function decodeWireMessage(bytes: Bytes): unknown {
  return parseCanonical(bytes, { maxBytes: MAX_MESSAGE_BYTES, maxDepth: 24, maxKeys: 4096 });
}

/**
 * Defence-in-depth: refuse to *produce* or accept a message that contains a
 * field name that could denote secret key material.  The schemas already
 * forbid these via `onlyKeys`, but this guard catches a future schema mistake
 * (or a device trying to push secret data into an allowed-but-unchecked spot)
 * before it reaches logs, disk, or the UI.
 */
const SECRET_FIELD_PATTERN =
  /^(seed|mnemonic|mnemonicPhrase|entropy|xprv|xpriv|priv|private|privkey|privateKey|secret|secretKey|passphrase|pin|password|recovery|masterKey|rootKey|sessionSecret)$/i;

export function assertNoSecretFields(value: unknown, path = "$"): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) assertNoSecretFields(value[i], `${path}[${i}]`);
    return;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_FIELD_PATTERN.test(k)) {
      fail("POLICY_VIOLATION", `protocol message contains a forbidden secret-bearing field '${k}' at ${path}`);
    }
    assertNoSecretFields(v, `${path}.${k}`);
  }
}

/** Validate a firmware measurement object shared by several messages. */
export interface FirmwareMeasurement {
  readonly version: string;
  readonly digest: string;
  readonly secureVersion: number;
}

const FW_MEAS_FIELDS = ["version", "digest", "secureVersion"] as const;

export function parseFirmwareMeasurement(v: unknown, what: string): FirmwareMeasurement {
  const o = asObject(v, what);
  onlyKeys(o, FW_MEAS_FIELDS, what);
  const version = readVersion(req(o, "version"), `${what}.version`);
  const digest = asString(req(o, "digest"), `${what}.digest`, 64);
  readBytes(digest, `${what}.digest`, 32);
  const secureVersion = asInt(req(o, "secureVersion"), `${what}.secureVersion`, 0, 0xffffff);
  return { version, digest, secureVersion };
}

export { asBool };
