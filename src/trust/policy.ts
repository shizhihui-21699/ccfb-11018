/**
 * Bill of Materials (BOM) and firmware/policy bundles.
 *
 * The factory, at manufacturing time, for each serial:
 *   1. knows exactly which component keys (SE, MCU, display controller, flash)
 *      were installed, and the attestation (SE) key;
 *   2. signs a `bomDigest` = H(domain, sorted[{type,pub}]) into the DAK cert.
 *   3. signs a *policy bundle* naming the firmware digests / secure-boot
 *      versions / minimum counters that are legitimate for that model.
 *
 * Offline verification works because everything the host needs to decide
 * "genuine and unmodified" is signed data carried with the device or shipped
 * inside the host app, never a network call.
 *
 * Two independent checks against component swap:
 *  - **Structural**: the set of component keys the device presents, when hashed,
 *    must equal the `bomDigest` the CA signed for this serial (see certs.ts).
 *  - **Presence**: each component must answer a fresh challenge with its key
 *    (see attestation/).  A swapped chip that merely *copies* keys would still
 *    have to sign live — which is the whole point of binding to a nonce.
 */

import { asArray, asInt, asObject, asString, canonicalString, onlyKeys, parseCanonical, req } from "../util/canonical.ts";
import { fail } from "../util/errors.ts";
import { b64u, b64uDecode, concat, utf8Encode, type Bytes } from "../util/bytes.ts";
import {
  digestOf,
  ed25519Verify,
  SIG_LEN,
  type Ed25519PublicKey,
  type Ed25519Signer,
} from "../crypto/primitives.ts";
import {
  isComponentType,
  type CertSubject,
  type ComponentType,
} from "./certs.ts";

// ---------------------------------------------------------------------------
// BOM digest
// ---------------------------------------------------------------------------

export interface BomEntry {
  readonly type: ComponentType;
  /** Raw Ed25519 public key of the component, base64url. */
  readonly pub: string;
}

/**
 * Compute the BOM digest for a set of components.
 *
 * - Sorted by (type, pub) using the *decoded* key so two encodings can't order
 *   differently.
 * - Type must appear exactly once (one SE, one MCU, ...).
 * - The attestation key IS one of the components (type "se" here) — it is
 *   included so the anchor is inside the signed BOM too.
 */
export async function computeBomDigest(entries: ReadonlyArray<BomEntry>): Promise<Bytes> {
  if (entries.length === 0) fail("BOM_INCOMPLETE", "bom: empty");
  if (entries.length > 32) fail("BOM_INCOMPLETE", "bom: too many entries");
  const seen = new Set<ComponentType>();
  const norm: Array<{ type: string; pub: string }> = [];
  for (const e of entries) {
    if (!isComponentType(e.type)) fail("BOM_INCOMPLETE", "bom: unknown component type");
    if (seen.has(e.type)) fail("BOM_INCOMPLETE", `bom: duplicate component type '${e.type}'`);
    seen.add(e.type);
    let raw: Bytes;
    try {
      raw = b64uDecode(e.pub);
    } catch {
      fail("BOM_INCOMPLETE", "bom: invalid component key encoding");
    }
    if (raw.length !== 32) fail("BOM_INCOMPLETE", "bom: component key must be 32 bytes");
    norm.push({ type: e.type, pub: b64u(raw) });
  }
  norm.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : a.pub < b.pub ? -1 : a.pub > b.pub ? 1 : 0));
  return digestOf("bom-digest/v1", norm);
}

/** The BOM entries that a set of verified component certs implies. */
export function bomFromSubjects(subjects: ReadonlyArray<CertSubject>): BomEntry[] {
  const out: BomEntry[] = [];
  for (const s of subjects) {
    if (s.role !== "component" && s.role !== "attestation") continue;
    if (!s.type && s.role !== "attestation") continue;
    out.push({ type: (s.type ?? "se") as ComponentType, pub: s.pub });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Firmware / model policy bundle
// ---------------------------------------------------------------------------

export interface FirmwareEntry {
  readonly version: string;
  /** SHA-256 of the full firmware image (base64url). */
  readonly digest: string;
  /** Monotonic secure-boot version; the device may not report lower. */
  readonly secureVersion: number;
  /** True if factory allows this firmware to be trusted for asset operations. */
  readonly approved: boolean;
}

export interface ModelPolicy {
  readonly model: string;
  /** Issue time / expiry for the offline bundle (seconds since epoch). */
  readonly issuedAt: number;
  readonly notAfter: number;
  /** Monotonic policy version — a host must reject older than it has seen. */
  readonly policyVersion: number;
  readonly firmware: ReadonlyArray<FirmwareEntry>;
  /** Component types this model must present. */
  readonly requiredComponents: ReadonlyArray<ComponentType>;
  /** Serials explicitly revoked by the factory (recalled / compromised). */
  readonly revokedSerials: ReadonlyArray<string>;
  /** Attestation key kids revoked (leaked SE). */
  readonly revokedKeyIds: ReadonlyArray<string>;
}

export interface PolicyBundle {
  readonly v: 1;
  readonly kind: "policy";
  readonly policies: ReadonlyArray<ModelPolicy>;
  readonly issuerKid: string;
  readonly sig: string;
}

const POLICY_FIELDS = ["model", "issuedAt", "notAfter", "policyVersion", "firmware", "requiredComponents", "revokedSerials", "revokedKeyIds"] as const;
const FW_FIELDS = ["version", "digest", "secureVersion", "approved"] as const;
const BUNDLE_FIELDS = ["v", "kind", "policies", "issuerKid", "sig"] as const;

const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?$/;
const KID_RE = /^[A-Za-z0-9_-]{43}$/;

export function parseFirmwareEntry(v: unknown): FirmwareEntry {
  const o = asObject(v, "policy.firmware[]");
  onlyKeys(o, FW_FIELDS, "policy.firmware[]");
  const version = asString(req(o, "version"), "firmware.version", 32);
  if (!VERSION_RE.test(version)) fail("FIRMWARE_DIGEST_INVALID", "firmware: bad version string");
  const digest = asString(req(o, "digest"), "firmware.digest", 64);
  if (safeB64(digest, "firmware.digest").length !== 32) fail("FIRMWARE_DIGEST_INVALID", "firmware: bad digest");
  const secureVersion = asInt(req(o, "secureVersion"), "firmware.secureVersion", 0, 0xffffff);
  const approvedRaw = req(o, "approved");
  if (typeof approvedRaw !== "boolean") fail("MALFORMED_MESSAGE", "firmware.approved: expected boolean");
  return { version, digest, secureVersion, approved: approvedRaw };
}

export function parseModelPolicy(v: unknown): ModelPolicy {
  const o = asObject(v, "policy");
  onlyKeys(o, POLICY_FIELDS, "policy");
  const model = asString(req(o, "model"), "policy.model", 32);
  if (!/^[A-Z0-9][A-Z0-9-]{1,31}$/.test(model)) fail("MALFORMED_MESSAGE", "policy.model: invalid");
  const issuedAt = asInt(req(o, "issuedAt"), "policy.issuedAt", 0, 4_102_444_800);
  const notAfter = asInt(req(o, "notAfter"), "policy.notAfter", 0, 4_102_444_800);
  if (notAfter <= issuedAt) fail("MALFORMED_MESSAGE", "policy: notAfter <= issuedAt");
  const policyVersion = asInt(req(o, "policyVersion"), "policy.policyVersion", 0, Number.MAX_SAFE_INTEGER);
  const firmware = asArray(req(o, "firmware"), "policy.firmware").map(parseFirmwareEntry);
  if (firmware.length === 0) fail("MALFORMED_MESSAGE", "policy: empty firmware list");
  if (firmware.length > 256) fail("FIELD_OUT_OF_RANGE", "policy: too many firmware entries");
  // Unique versions and unique digests.
  const versions = new Set<string>();
  const digests = new Set<string>();
  for (const f of firmware) {
    if (versions.has(f.version)) fail("MALFORMED_MESSAGE", "policy: duplicate firmware version");
    if (digests.has(f.digest)) fail("MALFORMED_MESSAGE", "policy: duplicate firmware digest");
    versions.add(f.version);
    digests.add(f.digest);
  }
  const rcRaw = asArray(req(o, "requiredComponents"), "policy.requiredComponents");
  if (rcRaw.length === 0 || rcRaw.length > 8) fail("MALFORMED_MESSAGE", "policy: bad requiredComponents");
  const requiredComponents: ComponentType[] = [];
  const rcSeen = new Set<string>();
  for (const t of rcRaw) {
    const s = asString(t, "policy.requiredComponents[]", 16);
    if (!isComponentType(s)) fail("MALFORMED_MESSAGE", "policy: unknown required component");
    if (rcSeen.has(s)) fail("MALFORMED_MESSAGE", "policy: duplicate required component");
    rcSeen.add(s);
    requiredComponents.push(s);
  }
  const revokedSerials = asArray(req(o, "revokedSerials"), "policy.revokedSerials").map((s) => {
    const str = asString(s, "policy.revokedSerials[]", 32);
    if (!/^[A-Z0-9][A-Z0-9-]{3,31}$/.test(str)) fail("MALFORMED_MESSAGE", "policy: bad revoked serial");
    return str;
  });
  const revokedKeyIds = asArray(req(o, "revokedKeyIds"), "policy.revokedKeyIds").map((s) => {
    const str = asString(s, "policy.revokedKeyIds[]", 64);
    if (!KID_RE.test(str)) fail("MALFORMED_MESSAGE", "policy: bad revoked kid");
    return str;
  });
  if (revokedSerials.length > 100_000 || revokedKeyIds.length > 100_000) {
    fail("FIELD_OUT_OF_RANGE", "policy: revocation list too large");
  }
  return {
    model,
    issuedAt,
    notAfter,
    policyVersion,
    firmware,
    requiredComponents,
    revokedSerials: [...new Set(revokedSerials)],
    revokedKeyIds: [...new Set(revokedKeyIds)],
  };
}

function policySigningBytes(bundle: Omit<PolicyBundle, "sig">): Bytes {
  const body = {
    v: bundle.v,
    kind: bundle.kind,
    policies: bundle.policies,
    issuerKid: bundle.issuerKid,
  };
  return concat(utf8Encode("policy/v1\u0000"), utf8Encode(canonicalString(body)));
}

export async function issuePolicyBundle(
  issuer: Ed25519Signer,
  policies: ReadonlyArray<ModelPolicy>,
): Promise<PolicyBundle> {
  const body = { v: 1 as const, kind: "policy" as const, policies, issuerKid: issuer.public.kid };
  const sig = await issuer.sign(policySigningBytes(body));
  return { ...body, sig: b64u(sig) };
}

export function encodePolicyBundle(b: PolicyBundle): string {
  return canonicalString(b);
}

export function parsePolicyBundle(input: unknown): PolicyBundle {
  const o = asObject(input, "policy-bundle");
  onlyKeys(o, BUNDLE_FIELDS, "policy-bundle");
  if (asInt(req(o, "v"), "policy-bundle.v", 1, 1) !== 1) fail("MALFORMED_MESSAGE", "policy: unsupported version");
  if (asString(req(o, "kind"), "policy-bundle.kind", 8) !== "policy") fail("MALFORMED_MESSAGE", "policy: bad kind");
  const policies = asArray(req(o, "policies"), "policy-bundle.policies").map(parseModelPolicy);
  if (policies.length === 0 || policies.length > 4096) fail("MALFORMED_MESSAGE", "policy: bad policies count");
  const models = new Set<string>();
  for (const p of policies) {
    if (models.has(p.model)) fail("MALFORMED_MESSAGE", "policy: duplicate model");
    models.add(p.model);
  }
  const issuerKid = asString(req(o, "issuerKid"), "policy-bundle.issuerKid", 64);
  if (safeB64(issuerKid, "policy-bundle.issuerKid").length !== 32) fail("MALFORMED_MESSAGE", "policy: bad issuerKid");
  const sig = asString(req(o, "sig"), "policy-bundle.sig", 128);
  if (safeB64(sig, "policy-bundle.sig").length !== SIG_LEN) fail("MALFORMED_MESSAGE", "policy: bad signature");
  return { v: 1, kind: "policy", policies, issuerKid, sig };
}

export function parsePolicyBundleBytes(bytes: Bytes): PolicyBundle {
  const v = parseCanonical(bytes, { maxBytes: 8 << 20, maxDepth: 16, maxKeys: 8192 });
  return parsePolicyBundle(v);
}

export async function verifyPolicyBundle(
  bundle: PolicyBundle,
  issuer: Ed25519PublicKey,
): Promise<boolean> {
  if (bundle.issuerKid !== issuer.kid) return false;
  const body: Omit<PolicyBundle, "sig"> = {
    v: bundle.v,
    kind: bundle.kind,
    policies: bundle.policies,
    issuerKid: bundle.issuerKid,
  };
  return ed25519Verify(issuer, policySigningBytes(body), safeB64(bundle.sig, "policy.sig"));
}

export function findPolicy(bundle: PolicyBundle, model: string): ModelPolicy | undefined {
  return bundle.policies.find((p) => p.model === model);
}

/** Look up a firmware entry by version, requiring an exact digest match. */
export function matchFirmware(policy: ModelPolicy, version: string, digest: string): FirmwareEntry | undefined {
  return policy.firmware.find((f) => f.version === version && f.digest === digest);
}

function safeB64(s: string, what: string): Bytes {
  try {
    return b64uDecode(s);
  } catch {
    fail("MALFORMED_MESSAGE", `${what}: bad base64url`);
  }
}
