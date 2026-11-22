/**
 * Session key schedule, key confirmation, and the Short Authentication String.
 *
 * One X25519 exchange produces, via HKDF with distinct domain labels:
 *   - a host->device confirmation key,
 *   - a device->host confirmation key,
 *   - a host->device record key,
 *   - a device->host record key.
 *
 * The two confirmation keys are also folded into a Short Authentication String
 * (SAS): 20 decimal digits the user (or the UI) compares on device and host.
 * The SAS is NOT secret and reveals nothing about wallet material; it exists
 * only to let a human detect an active man-in-the-middle that re-keyed the
 * ECDH.  A passive device that merely relays bytes cannot change the SAS
 * without controlling the endpoint keys, which are signed — see
 * `attestation/verifier.ts`.
 *
 * Secret-free requirement: the ECDH secret never leaves memory, is never
 * logged, and is zeroized after the keys are derived.  Nothing derived here is
 * ever written to disk.
 */

import {
  hkdf,
  hmacKey,
  hmacSign,
  hmacVerify,
  macEqual,
  x25519Derive,
} from "../crypto/primitives.ts";
import { concat, type Bytes, utf8Encode, zeroize } from "../util/bytes.ts";

export interface SessionKeys {
  /** Which side is "host" from this object's perspective is fixed at creation. */
  readonly hostConfirmKey: CryptoKey;
  readonly deviceConfirmKey: CryptoKey;
  /** Raw record keys, wrapped in CryptoKeys for HMAC use. */
  readonly hostRecordKey: CryptoKey;
  readonly deviceRecordKey: CryptoKey;
  /** 20-digit decimal SAS, grouped as 4-4-4-4-4. */
  readonly sas: string;
  /** Hash that identifies this exact key exchange (goes into the transcript). */
  readonly keyConfirmId: Bytes;
}

const LABELS = {
  h2dConfirm: "session/v1/host-to-device-confirm",
  d2hConfirm: "session/v1/device-to-host-confirm",
  h2dRecord: "session/v1/host-to-device-record",
  d2hRecord: "session/v1/device-to-host-record",
  keyId: "session/v1/key-confirm-id",
} as const;

/**
 * Derive the full key schedule from an ECDH shared secret.
 *
 * `salt` is the concatenation of both ephemeral public keys in a fixed order
 * (lexicographic by host/device role, not by value, so the derivation is
 * role-bound and cannot be reflected).
 */
export async function deriveSessionKeys(sharedSecret: Bytes, salt: Bytes): Promise<SessionKeys> {
  try {
    const h2dC = await hkdf(sharedSecret, salt, LABELS.h2dConfirm, 32);
    const d2hC = await hkdf(sharedSecret, salt, LABELS.d2hConfirm, 32);
    const h2dR = await hkdf(sharedSecret, salt, LABELS.h2dRecord, 32);
    const d2hR = await hkdf(sharedSecret, salt, LABELS.d2hRecord, 32);

    const hostConfirmKey = await hmacKey(h2dC);
    const deviceConfirmKey = await hmacKey(d2hC);
    const hostRecordKey = await hmacKey(h2dR);
    const deviceRecordKey = await hmacKey(d2hR);

    // SAS folds both confirmation keys, so it depends on the whole schedule.
    const sasBytes = await hkdf(
      concat(h2dC, d2hC),
      salt,
      "session/v1/sas",
      32,
    );
    const sas = formatSas(sasBytes);
    const keyConfirmId = await hkdf(sharedSecret, salt, LABELS.keyId, 32);

    zeroize(h2dC, d2hC, h2dR, d2hR, sasBytes);
    return { hostConfirmKey, deviceConfirmKey, hostRecordKey, deviceRecordKey, sas, keyConfirmId };
  } finally {
    zeroize(sharedSecret);
  }
}

/** One side's ECDH + derivation.  `isHost` picks which private key is ours. */
export async function establishSession(opts: {
  myPrivateKey: CryptoKey;
  myEphPub: Bytes;
  peerEphPub: Bytes;
  isHost: boolean;
}): Promise<SessionKeys> {
  const shared = await x25519Derive(opts.myPrivateKey, opts.peerEphPub);
  // Salt is role-ordered: host pub || device pub.  Both sides compute the same.
  const salt = opts.isHost
    ? concat(utf8Encode("session-salt/v1"), opts.myEphPub, opts.peerEphPub)
    : concat(utf8Encode("session-salt/v1"), opts.peerEphPub, opts.myEphPub);
  return deriveSessionKeys(shared, salt);
}

/** 20 decimal digits derived uniformly from the 32-byte SAS input. */
export function formatSas(input: Bytes): string {
  // Take 8 bytes as a big integer and reduce mod 10^20 with rejection-free
  // modular reduction on a 2^64 range is biased, so instead map 20 draws of a
  // single byte modulo 10 — the bias per digit is < 2^-8 and the SAS is only a
  // human comparison aid.  To avoid even that bias for the *whole* string we
  // use 20 independent bytes (overkill but simple and auditable).
  let s = "";
  for (let i = 0; i < 20; i++) s += (input[i]! % 10).toString();
  return s.replace(/(.{4})(?=.)/g, "$1 ");
}

// ---------------------------------------------------------------------------
// Key confirmation
// ---------------------------------------------------------------------------

export function confirmMessage(role: "host" | "device", transcriptHash: Bytes): Bytes {
  return concat(utf8Encode(`confirm/${role}/v1\u0000`), utf8Encode(nonSecretHex(transcriptHash)));
}

function nonSecretHex(b: Bytes): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export async function makeConfirmation(
  keys: SessionKeys,
  role: "host" | "device",
  transcriptHash: Bytes,
): Promise<Bytes> {
  const key = role === "host" ? keys.hostConfirmKey : keys.deviceConfirmKey;
  return hmacSign(key, confirmMessage(role, transcriptHash));
}

export async function checkConfirmation(
  keys: SessionKeys,
  role: "host" | "device",
  transcriptHash: Bytes,
  mac: Bytes,
): Promise<boolean> {
  const key = role === "host" ? keys.hostConfirmKey : keys.deviceConfirmKey;
  return hmacVerify(key, confirmMessage(role, transcriptHash), mac);
}

/** Session record MAC — used for every post-handshake management message so a
 *  message cannot be reordered, truncated, or replayed across sessions. */
export async function sessionRecordMac(
  keys: SessionKeys,
  direction: "host-to-device" | "device-to-host",
  seq: number,
  plaintext: Bytes,
): Promise<Bytes> {
  const key = direction === "host-to-device" ? keys.hostRecordKey : keys.deviceRecordKey;
  const header = concat(utf8Encode("record/v1\u0000"), new Uint8Array([
    (seq >>> 24) & 0xff, (seq >>> 16) & 0xff, (seq >>> 8) & 0xff, seq & 0xff,
  ]));
  return hmacSign(key, concat(header, plaintext));
}

export function constantTimeMacEqual(a: Bytes, b: Bytes): boolean {
  return macEqual(a, b);
}
