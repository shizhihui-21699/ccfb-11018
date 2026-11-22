/**
 * Certificate model: a small, purpose-built PKI.
 *
 * Design constraints that shaped this:
 *  - The host must verify **offline**.  The only thing preinstalled is the
 *    factory root public key.  Everything else travels with the device as a
 *    certificate bundle whose signatures chain to that root.
 *  - Every certificate is bound to a *purpose* (role) and, for device parts,
 *    to a *serial* and the device's *BOM digest*.  A certificate that is valid
 *    for one purpose must never be accepted for another (no "confused deputy"
 *    across the CA tree).
 *  - Signatures are over canonical JSON, with a domain label, so a certificate
 *    byte string can never be reinterpreted as another signed structure.
 *
 * Threat note (please read):
 *  Certificates prove *factory issuance*.  They do NOT by themselves prove the
 *  key is present in the device right now — an attacker who studied a genuine
 *  device can copy its public keys indefinitely.  Presence is proven separately
 *  by a fresh, challenge-bound signature from each component (see
 *  `attestation/`).  This file only establishes "who is allowed to sign what".
 */

import { canonicalString, parseCanonical, onlyKeys, asObject, asString, asInt, req, opt } from "../util/canonical.ts";
import { fail } from "../util/errors.ts";
import { b64u, b64uDecode, concat, type Bytes, utf8Encode } from "../util/bytes.ts";
import {
  domainHash,
  ed25519Verify,
  importEd25519Public,
  sha256,
  SIG_LEN,
  type Ed25519PublicKey,
  type Ed25519Signer,
} from "../crypto/primitives.ts";

export type CertRole = "device-ca" | "attestation" | "component" | "policy" | "firmware";

export type ComponentType = "se" | "mcu" | "display" | "flash";

export const COMPONENT_TYPES: ReadonlyArray<ComponentType> = ["se", "mcu", "display", "flash"];

export function isComponentType(s: string): s is ComponentType {
  return (COMPONENT_TYPES as ReadonlyArray<string>).includes(s);
}

export interface CertSubject {
  /** Raw Ed25519 public key, base64url. */
  readonly pub: string;
  readonly role: CertRole;
  /** Component type — required when role === "component". */
  readonly type?: ComponentType;
  /** Device serial — required for device-scoped certs. */
  readonly serial?: string;
  /** Device model — required for device-scoped certs. */
  readonly model?: string;
  /**
   * SHA-256 over the canonical list of {type,pub} of every component the
   * factory installed in this serial, INCLUDING the attestation (SE) key.
   * Anchored in the DAK cert so the full expected BOM is signed by the CA.
   */
  readonly bomDigest?: string;
}

export interface Certificate {
  readonly v: 1;
  readonly kind: "cert";
  readonly subject: CertSubject;
  /** Key id of the issuer (base64url SHA-256 of issuer raw pubkey). */
  readonly issuerKid: string;
  readonly issuedAt: number;
  readonly notAfter: number;
  readonly sig: string;
}

const CERT_FIELDS = ["v", "kind", "subject", "issuerKid", "issuedAt", "notAfter", "sig"] as const;
const SERIAL_RE = /^[A-Z0-9][A-Z0-9-]{3,31}$/;

export function validateSerial(serial: string): string {
  if (!SERIAL_RE.test(serial)) fail("CERT_PARSE_ERROR", "serial: invalid format");
  return serial;
}

/** The bytes covered by a certificate's signature (everything except `sig`). */
export function certSigningBytes(cert: Omit<Certificate, "sig">): Bytes {
  const body = {
    v: cert.v,
    kind: cert.kind,
    subject: cert.subject,
    issuerKid: cert.issuerKid,
    issuedAt: cert.issuedAt,
    notAfter: cert.notAfter,
  };
  return concat(utf8Encode("cert/v1\u0000"), utf8Encode(canonicalString(body)));
}

export async function issueCert(
  issuer: Ed25519Signer,
  subject: CertSubject,
  validity: { issuedAt: number; notAfter: number },
): Promise<Certificate> {
  if (validity.notAfter <= validity.issuedAt) fail("INTERNAL_ERROR", "cert: notAfter must be after issuedAt");
  const body = {
    v: 1 as const,
    kind: "cert" as const,
    subject,
    issuerKid: issuer.public.kid,
    issuedAt: validity.issuedAt,
    notAfter: validity.notAfter,
  };
  const sig = await issuer.sign(certSigningBytes(body));
  return { ...body, sig: b64u(sig) };
}

/** Encode a certificate to canonical JSON text. */
export function encodeCert(cert: Certificate): string {
  return canonicalString(cert);
}

/** Parse and structurally validate a certificate (does NOT check signature). */
export function parseCert(input: unknown): Certificate {
  const obj = asObject(input, "cert");
  onlyKeys(obj, CERT_FIELDS, "cert");
  if (asInt(req(obj, "v"), "cert.v", 1, 1) !== 1) fail("CERT_PARSE_ERROR", "cert: unsupported version");
  if (asString(req(obj, "kind"), "cert.kind", 8) !== "cert") fail("CERT_PARSE_ERROR", "cert: bad kind");
  const subjObj = asObject(req(obj, "subject"), "cert.subject");
  const roleRaw = asString(req(subjObj, "role"), "cert.subject.role", 32);
  const roles: ReadonlyArray<string> = ["device-ca", "attestation", "component", "policy", "firmware"];
  if (!roles.includes(roleRaw)) fail("CERT_PARSE_ERROR", "cert: unknown role");
  const role = roleRaw as CertRole;

  const pub = asString(req(subjObj, "pub"), "cert.subject.pub", 64);
  let pubBytes: Bytes;
  try {
    pubBytes = b64uDecode(pub);
  } catch {
    fail("CERT_PARSE_ERROR", "cert: bad subject public key");
  }
  if (pubBytes.length !== 32) fail("CERT_PARSE_ERROR", "cert: subject key must be 32 bytes");

  const allowedSubj: string[] = ["pub", "role"];
  const subject: {
    pub: string;
    role: CertRole;
    type?: ComponentType;
    serial?: string;
    model?: string;
    bomDigest?: string;
  } = { pub, role };

  if (role === "component") {
    const t = asString(req(subjObj, "type"), "cert.subject.type", 16);
    if (!isComponentType(t)) fail("CERT_PARSE_ERROR", "cert: unknown component type");
    subject.type = t;
    allowedSubj.push("type");
  } else if (opt(subjObj, "type") !== undefined) {
    fail("CERT_PARSE_ERROR", "cert: 'type' only allowed for component certs");
  }

  if (role === "attestation" || role === "component") {
    subject.serial = validateSerial(asString(req(subjObj, "serial"), "cert.subject.serial", 32));
    subject.model = asString(req(subjObj, "model"), "cert.subject.model", 32);
    allowedSubj.push("serial", "model");
  }
  if (role === "attestation") {
    const bom = asString(req(subjObj, "bomDigest"), "cert.subject.bomDigest", 64);
    const bomBytes = safeB64(bom, "cert.subject.bomDigest");
    if (bomBytes.length !== 32) fail("CERT_PARSE_ERROR", "cert: bomDigest must be 32 bytes");
    subject.bomDigest = bom;
    allowedSubj.push("bomDigest");
  }
  onlyKeys(subjObj, allowedSubj, "cert.subject");

  const issuerKid = asString(req(obj, "issuerKid"), "cert.issuerKid", 64);
  if (safeB64(issuerKid, "cert.issuerKid").length !== 32) fail("CERT_PARSE_ERROR", "cert: bad issuerKid");
  const issuedAt = asInt(req(obj, "issuedAt"), "cert.issuedAt", 0, 4_102_444_800);
  const notAfter = asInt(req(obj, "notAfter"), "cert.notAfter", 0, 4_102_444_800);
  if (notAfter <= issuedAt) fail("CERT_PARSE_ERROR", "cert: notAfter <= issuedAt");
  if (notAfter - issuedAt > 40 * 365 * 86400) fail("FIELD_OUT_OF_RANGE", "cert: validity too long");
  const sig = asString(req(obj, "sig"), "cert.sig", 128);
  if (safeB64(sig, "cert.sig").length !== SIG_LEN) fail("CERT_PARSE_ERROR", "cert: bad signature length");

  return { v: 1, kind: "cert", subject, issuerKid, issuedAt, notAfter, sig };
}

function safeB64(s: string, what: string): Bytes {
  try {
    return b64uDecode(s);
  } catch {
    fail("CERT_PARSE_ERROR", `${what}: bad base64url`);
  }
}

/** Verify a certificate was signed by `issuer`. */
export async function verifyCertSignature(cert: Certificate, issuer: Ed25519PublicKey): Promise<boolean> {
  if (cert.issuerKid !== issuer.kid) return false;
  const body: Omit<Certificate, "sig"> = {
    v: cert.v,
    kind: cert.kind,
    subject: cert.subject,
    issuerKid: cert.issuerKid,
    issuedAt: cert.issuedAt,
    notAfter: cert.notAfter,
  };
  return ed25519Verify(issuer, certSigningBytes(body), safeB64(cert.sig, "cert.sig"));
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

export interface TrustRoot {
  /** Factory root public key — the single preinstalled offline anchor. */
  readonly root: Ed25519PublicKey;
}

export interface VerifiedChain {
  readonly leaf: Certificate;
  readonly chain: ReadonlyArray<Certificate>;
}

/**
 * Validate a certificate bundle against the pinned root.
 *
 * A device bundle legitimately contains siblings: the attestation leaf, each
 * component certificate, and the CA certificate that issued all of them.  So we
 * do NOT require every cert to lie on the leaf's path.  Instead we require:
 *
 *   - every certificate in the bundle chains to the pinned root (same issuer
 *     rules, bounded depth, no cycles),
 *   - no duplicate certificates,
 *   - the first certificate is treated as the leaf by the caller.
 *
 * Rejecting "chains to some other root" is what stops a device from smuggling
 * an extra certificate that a downstream component might honour.
 */
export async function verifyChain(
  bundleInput: ReadonlyArray<unknown>,
  root: TrustRoot,
  opts: { now: number; clockSkewSec?: number; maxDepth?: number },
): Promise<VerifiedChain> {
  const maxDepth = opts.maxDepth ?? 4;
  const skew = opts.clockSkewSec ?? 300;
  if (bundleInput.length === 0) fail("CERT_CHAIN_INCOMPLETE", "empty certificate bundle");
  if (bundleInput.length > 16) fail("CERT_CHAIN_INCOMPLETE", "certificate bundle too large");
  const certs = bundleInput.map((c) => parseCert(c));
  if (new Set(certs.map(certIdentity)).size !== certs.length) {
    fail("CERT_CHAIN_INCOMPLETE", "duplicate certificate in bundle");
  }
  const leaf = certs[0]!;

  // Enforce validity on every cert with bounded clock skew.
  for (const c of certs) {
    if (opts.now + skew < c.issuedAt) fail("CERT_NOT_YET_VALID", "certificate not yet valid");
    if (opts.now - skew > c.notAfter) fail("CERT_EXPIRED", "certificate expired");
  }

  // Index subjects by their key id so issuer lookup is by *hash*, not raw key.
  const subjectKidToCert = new Map<string, Certificate>();
  for (const c of certs) {
    const kid = b64u(await sha256(safeB64(c.subject.pub, "cert.subject.pub")));
    const prior = subjectKidToCert.get(kid);
    if (prior && certIdentity(prior) !== certIdentity(c)) {
      fail("CERT_CHAIN_INCOMPLETE", "two certificates claim the same subject key");
    }
    subjectKidToCert.set(kid, c);
  }

  // Walk each certificate to the root independently.
  //
  // ROLE ENFORCEMENT (critical): the hierarchy is exactly two levels —
  //   root -> device-ca -> {attestation, component, policy}
  // A certificate may only be *issued* by a `device-ca` certificate, and a
  // `device-ca` certificate may only be issued by the root.  Without this
  // check, the holder of ANY certified leaf key (for example a genuine MCU
  // recovered from a scrapped unit) could mint a forged attestation certificate
  // for a swap-in fake Secure Element, and the chain would still reach the
  // root.  That is a complete break of device identity, so it is enforced here
  // for every certificate in the bundle, not just the leaf's path.
  for (const start of certs) {
    let current = start;
    const seen = new Set<string>([certIdentity(current)]);
    for (let depth = 0; ; depth++) {
      if (depth > maxDepth) fail("CERT_CHAIN_INCOMPLETE", "certificate chain too long");
      if (current.issuerKid === root.root.kid) {
        // Only a device-ca may be signed directly by the root.
        if (current.subject.role !== "device-ca") {
          fail("CERT_KEY_USAGE", `a '${current.subject.role}' certificate may not be issued by the root`);
        }
        if (!(await verifyCertSignature(current, root.root))) {
          fail("CERT_SIGNATURE_INVALID", "root signature invalid");
        }
        break;
      }
      const issuer = subjectKidToCert.get(current.issuerKid);
      if (!issuer) fail("CERT_CHAIN_INCOMPLETE", "issuer certificate missing from bundle");
      // Only a device-ca may act as an issuer of any device-scoped cert.
      if (issuer.subject.role !== "device-ca") {
        fail("CERT_KEY_USAGE", `a '${issuer.subject.role}' certificate may not issue other certificates`);
      }
      // A device-ca must itself be signed by the root (no nested CAs).
      if (issuer.issuerKid !== root.root.kid) {
        fail("CERT_CHAIN_INCOMPLETE", "device-ca is not signed by the root");
      }
      if (seen.has(certIdentity(issuer))) fail("CERT_CHAIN_INCOMPLETE", "certificate cycle");
      seen.add(certIdentity(issuer));
      const issuerPub = await importEd25519Public(safeB64(issuer.subject.pub, "cert.subject.pub"));
      if (!(await verifyCertSignature(current, issuerPub))) {
        fail("CERT_SIGNATURE_INVALID", "certificate signature invalid");
      }
      current = issuer;
    }
  }

  return { leaf, chain: certs };
}

function certIdentity(c: Certificate): string {
  return `${c.subject.pub}|${c.issuerKid}|${c.issuedAt}|${c.sig}`;
}

/** Role/usage enforcement on the leaf.  Call after `verifyChain`. */
export function requireRole(cert: Certificate, role: CertRole, what: string): void {
  if (cert.subject.role !== role) fail("CERT_KEY_USAGE", `${what}: expected role '${role}', got '${cert.subject.role}'`);
}

/** Parse a certificate bundle from a canonical-JSON byte string. */
export function parseCertBundleBytes(bytes: Bytes): ReadonlyArray<unknown> {
  const v = parseCanonical(bytes, { maxBytes: 1 << 18, maxDepth: 16, maxKeys: 256 });
  if (!Array.isArray(v)) fail("CERT_PARSE_ERROR", "cert bundle: expected array");
  return v;
}

/** Hash of a certificate's DER-like canonical form, for pinning/revocation. */
export async function certFingerprint(cert: Certificate): Promise<Bytes> {
  return domainHash("cert-fingerprint/v1", utf8Encode(canonicalString(cert)));
}

/** Convenience: kid of a raw public key. */
export async function keyId(rawPub: Bytes): Promise<string> {
  return b64u(await sha256(rawPub));
}
