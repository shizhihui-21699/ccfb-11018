/**
 * The Attestation Statement: what the device asserts about itself, bound to
 * this session's nonces and ephemeral keys.
 *
 * Field types are explicit:
 *   - `attestationPub` and every component `pub` are *raw* Ed25519 public keys
 *     (base64url, 32 bytes).  Key *ids* (SHA-256 thumbprints) are never carried
 *     on the wire in the statement — the verifier derives them — so there is no
 *     way to confuse "the key" with "a hash of the key".
 *
 * The statement is signed by the Secure Element (SE) attestation key.  It lists
 * every component with:
 *   - its type and raw public key,
 *   - a per-component `challengeSig`: an Ed25519 signature over the session
 *     transcript produced by that component's OWN private key.
 *
 * Why per-component challengeSig matters
 * --------------------------------------
 * The SE signs "these are my components".  But a cloned SE (attacker copied
 * its keys from a real device they owned) could sign the same claim while the
 * MCU/display/flash have been swapped.  Requiring each component to sign the
 * live transcript forces the *actual present hardware* to prove possession of
 * the factory-issued key for its slot.  A swapped chip without the original
 * private key cannot produce a valid `challengeSig`; a swapped chip WITH the
 * original key is, functionally, the original chip (we cannot detect a
 * same-key re-packaging — documented limitation).
 *
 * What is deliberately absent
 * ---------------------------
 * No seed, xprv, mnemonic, PIN, passphrase, or any key derived from wallet
 * material ever appears here, nor in any signed structure.  Components sign a
 * challenge; they do not reveal what they sign it with.  The host cannot — and
 * must not — ask for anything more.
 */

import {
  asArray,
  asInt,
  asObject,
  asString,
  canonicalString,
  onlyKeys,
  req,
} from "../util/canonical.ts";
import { fail } from "../util/errors.ts";
import { b64u, concat, utf8Encode, type Bytes } from "../util/bytes.ts";
import { digestOf } from "../crypto/primitives.ts";
import { isComponentType, type ComponentType } from "../trust/certs.ts";
import {
  parseFirmwareMeasurement,
  readBytes,
  readModel,
  readPub,
  readSerial,
  readU32,
  type FirmwareMeasurement,
} from "../protocol/messages.ts";

export interface ComponentClaim {
  readonly type: ComponentType;
  /** Raw Ed25519 public key (base64url, 32 bytes) of the installed component. */
  readonly pub: string;
  /** Per-component signature over the challenge transcript. */
  readonly challengeSig: string;
  /** Component's own monotonic boot counter (anti-rollback / clone signal). */
  readonly bootCounter: number;
  /** Component firmware digest, base64url SHA-256. */
  readonly fwDigest: string;
}

export interface AttestationStatement {
  readonly v: 1;
  readonly kind: "statement";
  readonly serial: string;
  readonly model: string;
  /** Raw SE attestation public key (base64url, 32 bytes). */
  readonly attestationPub: string;
  readonly sessionId: string;
  readonly hostNonce: string;
  readonly deviceNonce: string;
  readonly hostEphPub: string;
  readonly deviceEphPub: string;
  readonly firmware: FirmwareMeasurement;
  /** SE monotonic counter; must not regress. */
  readonly seCounter: number;
  /** Device build/batch identifier for an additional pin. */
  readonly batch: string;
  readonly components: ReadonlyArray<ComponentClaim>;
}

const STATEMENT_FIELDS = [
  "v", "kind", "serial", "model", "attestationPub", "sessionId", "hostNonce",
  "deviceNonce", "hostEphPub", "deviceEphPub", "firmware", "seCounter", "batch",
  "components",
] as const;

const COMPONENT_FIELDS = ["type", "pub", "challengeSig", "bootCounter", "fwDigest"] as const;

function parseComponentClaim(v: unknown): ComponentClaim {
  const o = asObject(v, "statement.components[]");
  onlyKeys(o, COMPONENT_FIELDS, "statement.components[]");
  const typeRaw = asString(req(o, "type"), "component.type", 16);
  if (!isComponentType(typeRaw)) fail("MALFORMED_MESSAGE", "component: unknown type");
  const pub = readPub(req(o, "pub"), "component.pub");
  readBytes(req(o, "challengeSig"), "component.challengeSig", 64);
  const bootCounter = readU32(req(o, "bootCounter"), "component.bootCounter");
  const fwDigest = asString(req(o, "fwDigest"), "component.fwDigest", 64);
  readBytes(fwDigest, "component.fwDigest", 32);
  return {
    type: typeRaw,
    pub,
    challengeSig: asString(req(o, "challengeSig"), "component.challengeSig"),
    bootCounter,
    fwDigest,
  };
}

/** Parse a statement from a decoded JSON value.  Does not verify signatures. */
export function parseStatement(input: unknown): AttestationStatement {
  const o = asObject(input, "statement");
  onlyKeys(o, STATEMENT_FIELDS, "statement");
  if (asInt(req(o, "v"), "statement.v", 1, 1) !== 1) fail("MALFORMED_MESSAGE", "statement: unsupported version");
  if (asString(req(o, "kind"), "statement.kind", 16) !== "statement") fail("MALFORMED_MESSAGE", "statement: bad kind");
  const serial = readSerial(req(o, "serial"), "statement.serial");
  const model = readModel(req(o, "model"), "statement.model");
  const attestationPub = readPub(req(o, "attestationPub"), "statement.attestationPub");
  const sessionId = asString(req(o, "sessionId"), "statement.sessionId", 64);
  readBytes(sessionId, "statement.sessionId", 16);
  const hostNonce = asString(req(o, "hostNonce"), "statement.hostNonce", 64);
  readBytes(hostNonce, "statement.hostNonce", 32);
  const deviceNonce = asString(req(o, "deviceNonce"), "statement.deviceNonce", 64);
  readBytes(deviceNonce, "statement.deviceNonce", 32);
  const hostEphPub = asString(req(o, "hostEphPub"), "statement.hostEphPub", 64);
  readBytes(hostEphPub, "statement.hostEphPub", 32);
  const deviceEphPub = asString(req(o, "deviceEphPub"), "statement.deviceEphPub", 64);
  readBytes(deviceEphPub, "statement.deviceEphPub", 32);
  const firmware = parseFirmwareMeasurement(req(o, "firmware"), "statement.firmware");
  const seCounter = readU32(req(o, "seCounter"), "statement.seCounter");
  const batch = asString(req(o, "batch"), "statement.batch", 32);
  if (!/^[A-Z0-9][A-Z0-9-]{1,31}$/.test(batch)) fail("MALFORMED_MESSAGE", "statement.batch: invalid");
  const components = asArray(req(o, "components"), "statement.components").map(parseComponentClaim);
  if (components.length === 0 || components.length > 8) fail("MALFORMED_MESSAGE", "statement: bad component count");
  const types = new Set<string>();
  const pubs = new Set<string>();
  for (const c of components) {
    if (types.has(c.type)) fail("MALFORMED_MESSAGE", "statement: duplicate component type");
    if (pubs.has(c.pub)) fail("MALFORMED_MESSAGE", "statement: duplicate component key");
    types.add(c.type);
    pubs.add(c.pub);
  }
  return {
    v: 1,
    kind: "statement",
    serial,
    model,
    attestationPub,
    sessionId,
    hostNonce,
    deviceNonce,
    hostEphPub,
    deviceEphPub,
    firmware,
    seCounter,
    batch,
    components,
  };
}

/** Canonical bytes the SE signs (the whole statement value). */
export function statementSigningBytes(s: AttestationStatement): Bytes {
  return concat(utf8Encode("statement/v1\u0000"), utf8Encode(canonicalString(s)));
}

/**
 * Transcript hash that every component signs.  This is the single value that
 * binds "what the device claims" to "this session" and to "this exact wire
 * bytes".  Any change to any field of the statement (serial, keys, firmware,
 * counters) or to either nonce / ephemeral public key yields a different hash,
 * so a component's signature cannot be replayed into a different claim.
 *
 * Note the component signatures are *not* part of the signed transcript input
 * (they cannot sign themselves), but each signature covers every other field,
 * including the other components' signatures are excluded — that's fine: the
 * SE's outer statement signature covers the full component list including all
 * challengeSig values, so a component list cannot be edited without breaking
 * the SE signature.
 */
export async function statementTranscriptHash(s: AttestationStatement): Promise<Bytes> {
  return digestOf("statement-transcript/v1", {
    v: s.v,
    kind: s.kind,
    serial: s.serial,
    model: s.model,
    attestationPub: s.attestationPub,
    sessionId: s.sessionId,
    hostNonce: s.hostNonce,
    deviceNonce: s.deviceNonce,
    hostEphPub: s.hostEphPub,
    deviceEphPub: s.deviceEphPub,
    firmware: s.firmware,
    seCounter: s.seCounter,
    batch: s.batch,
    components: s.components.map((c) => ({
      type: c.type,
      pub: c.pub,
      bootCounter: c.bootCounter,
      fwDigest: c.fwDigest,
    })),
  });
}

export function encodeStatement(s: AttestationStatement): Bytes {
  return new TextEncoder().encode(canonicalString(s));
}

export { b64u };
