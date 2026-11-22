/**
 * The attestation verifier — the heart of the system.
 *
 * Given the parsed ATTEST flight, the host's own HELLO (nonce + ephemeral key),
 * the pinned root, and the verified policy bundle, decide whether the device is
 * genuine and unmodified.  Everything here runs offline.
 *
 * The checks, in order, and the attack each one stops:
 *
 *  1. Session binding      — statement echoes our sessionId/hostNonce/hostEphPub
 *                            and the ATTEST envelope matches the statement.
 *                            (stops a recorded attestation being replayed)
 *  2. Certificate chain    — every cert chains to the pinned root; validity
 *                            window honoured.  (stops forged issuance)
 *  3. Role binding         — leaf is an attestation cert with serial + model +
 *                            bomDigest; component certs carry serial + model.
 *                            (stops cross-device / cross-role key reuse)
 *  4. Statement signature  — the SE attestation key signs the statement.
 *  5. Identity match       — the statement's attestation key, the cert's key,
 *                            and the serial/model all agree.
 *  6. BOM recomputation    — H(component certs) == the CA-signed bomDigest.
 *                            (stops a swapped component with a different key)
 *  7. Per-component live signature — every component signs the transcript with
 *                            ITS key.  (stops a cloned SE vouching for swapped
 *                            silicon; forces the present hardware to prove it)
 *  8. Policy: model exists, not expired, component set == required, firmware
 *     digest in the approved list at/above the secure version, device not
 *     revoked, no key revoked.
 *  9. Rollback: secure version and counters not below the pinned maxima.
 * 10. User presence is reported to the caller (a separate, physical step).
 *
 * The verifier never sees, requests, or accepts secrets.  It only consumes
 * public keys, signatures, hashes and counters.
 */

import {
  ed25519Verify,
  importEd25519Public,
  sha256,
} from "../crypto/primitives.ts";
import { b64u, b64uDecode } from "../util/bytes.ts";
import { fail } from "../util/errors.ts";
import {
  computeBomDigest,
  findPolicy,
  matchFirmware,
  type PolicyBundle,
} from "../trust/policy.ts";
import {
  requireRole,
  verifyChain,
  type Certificate,
  type ComponentType,
  type TrustRoot,
} from "../trust/certs.ts";
import {
  parseStatement,
  statementSigningBytes,
  statementTranscriptHash,
  type AttestationStatement,
} from "../attestation/statement.ts";
import type { AttestMessage, HelloMessage } from "../protocol/messages.ts";

export interface VerifyInputs {
  readonly hello: HelloMessage;
  readonly attest: AttestMessage;
  readonly root: TrustRoot;
  readonly policy: PolicyBundle;
  /** Highest policyVersion this host has ever accepted (anti-downgrade). */
  readonly minPolicyVersion: number;
  /** Pinned state from the trust store, if the device is known. */
  readonly pinned?: PinnedState | undefined;
  /**
   * Resolve the pin from the *verified* serial (after the certificate and
   * statement are bound).  Preferred over `pinned` when the caller does not
   * know the serial in advance: the lookup key is the authenticated serial, so
   * a device cannot influence which pin is applied.
   */
  readonly resolvePin?: ((verifiedSerial: string) => PinnedState | undefined) | undefined;
  /** Current time (seconds).  Injected so tests are deterministic. */
  readonly now: number;
  /** Whether user presence is required by policy for the upcoming operation. */
  readonly requireUserPresence: boolean;
}

export interface PinnedState {
  readonly attestationPub: string;
  readonly bomDigest: string;
  readonly batch: string;
  /** type -> base64url SHA-256 thumbprint of the pinned component key. */
  readonly componentKids: Readonly<Record<string, string>>;
  readonly seCounter: number;
  readonly bootCounters: Readonly<Record<string, number>>;
  readonly secureVersion: number;
  readonly policyVersion: number;
}

export interface TrustedDevice {
  readonly serial: string;
  readonly model: string;
  readonly batch: string;
  /** base64url SHA-256 thumbprint of the SE attestation key. */
  readonly attestationKid: string;
  readonly attestationPub: string;
  readonly bomDigest: string;
  readonly componentPubs: Readonly<Record<string, string>>;
  readonly componentKids: Readonly<Record<string, string>>;
  readonly seCounter: number;
  readonly bootCounters: Readonly<Record<string, number>>;
  readonly firmware: { version: string; digest: string; secureVersion: number };
  readonly policyVersion: number;
  readonly statement: AttestationStatement;
  readonly certs: ReadonlyArray<Certificate>;
}

export interface VerifyResult {
  readonly ok: true;
  readonly device: TrustedDevice;
  /** True when this is the first time we see this serial (fresh pin). */
  readonly firstSight: boolean;
  /** Whether user presence still must be confirmed before asset operations. */
  readonly userPresenceRequired: boolean;
}

const CLOCK_SKEW = 300;

export async function verifyAttestation(inputs: VerifyInputs): Promise<VerifyResult> {
  const { hello, attest, root, policy, now } = inputs;

  // ---- 1. Session binding -------------------------------------------------
  if (attest.sessionId !== hello.sessionId) {
    fail("CHALLENGE_MISMATCH", "attest.sessionId does not match this session");
  }
  if (attest.hostNonce !== hello.hostNonce) {
    fail("CHALLENGE_MISMATCH", "attest echoed a different host nonce (possible replay)");
  }

  const statement = parseStatement(attest.statement);

  // The ATTEST envelope and the signed statement must agree on every binding
  // field.  A mismatch means the device signed one thing but sent another.
  if (
    statement.sessionId !== attest.sessionId ||
    statement.hostNonce !== attest.hostNonce ||
    statement.deviceNonce !== attest.deviceNonce ||
    statement.deviceEphPub !== attest.deviceEphPub ||
    statement.hostEphPub !== hello.hostEphPub
  ) {
    fail("TRANSCRIPT_MISMATCH", "ATTEST envelope and signed statement disagree on session binding");
  }

  // ---- 2. Certificate chain ----------------------------------------------
  const chain = await verifyChain(attest.certBundle, root, { now, clockSkewSec: CLOCK_SKEW });
  const attestationCert = chain.leaf;
  requireRole(attestationCert, "attestation", "leaf certificate");
  const componentCerts = chain.chain.slice(1).filter((c) => c.subject.role === "component");

  // ---- 3. Role/identity binding on the cert ------------------------------
  const certSerial = attestationCert.subject.serial;
  const certModel = attestationCert.subject.model;
  const certBom = attestationCert.subject.bomDigest;
  const certPub = attestationCert.subject.pub;
  if (!certSerial || !certModel || !certBom) {
    fail("CERT_KEY_USAGE", "attestation cert is missing serial/model/bomDigest");
  }
  if (statement.serial !== certSerial) {
    fail("DEVICE_MISMATCH", "statement serial does not match the certificate");
  }
  if (statement.model !== certModel) {
    fail("DEVICE_MISMATCH", "statement model does not match the certificate");
  }
  if (statement.attestationPub !== certPub) {
    fail("DEVICE_MISMATCH", "statement attestation key does not match the certificate");
  }

  // ---- 4. Statement signature -------------------------------------------
  const sePub = await importEd25519Public(b64uDecode(certPub));
  if (!(await ed25519Verify(sePub, statementSigningBytes(statement), b64uDecode(attest.statementSig)))) {
    fail("STATEMENT_SIGNATURE_INVALID", "attestation statement signature is invalid");
  }

  // ---- 5. Identity match -------------------------------------------------
  const seKid = sePub.kid;
  const componentPubByType: Record<string, string> = {};
  const componentKidByType: Record<string, string> = {};
  const claimTypes = new Set<ComponentType>();
  for (const c of statement.components) {
    if (claimTypes.has(c.type)) fail("MALFORMED_MESSAGE", "duplicate component type in statement");
    claimTypes.add(c.type);
    componentPubByType[c.type] = c.pub;
    componentKidByType[c.type] = b64u(await sha256(b64uDecode(c.pub)));
  }

  // ---- 6. BOM recomputation ---------------------------------------------
  // The BOM covers every installed component, with the SE represented by its
  // attestation certificate (the SE has no separate component cert).  Build it
  // from CA-signed data only, then require it to match the digest the CA signed
  // into the attestation cert.
  const bomEntries = [
    { type: "se" as const, pub: certPub },
    ...componentCerts.map((c) => {
      if (!c.subject.type) fail("CERT_KEY_USAGE", "component cert missing type");
      return { type: c.subject.type!, pub: c.subject.pub };
    }),
  ];
  for (const c of componentCerts) {
    if (c.subject.serial !== certSerial || c.subject.model !== certModel) {
      fail("COMPONENT_SERIAL_MISMATCH", "component certificate is bound to a different device");
    }
  }
  const recomputedBom = b64u(await computeBomDigest(bomEntries));
  if (recomputedBom !== certBom) {
    fail("BOM_DIGEST_MISMATCH", "component set does not match the factory-signed BOM digest");
  }

  // Build the authoritative type -> cert map (SE maps to the attestation cert).
  const certByType = new Map<ComponentType, Certificate>();
  certByType.set("se", attestationCert);
  for (const c of componentCerts) certByType.set(c.subject.type!, c);

  // Every certified key must appear (matching) in the statement, and the
  // statement must not list a component that has no certificate.
  for (const c of statement.components) {
    const cert = certByType.get(c.type);
    if (!cert) fail("COMPONENT_NOT_TRUSTED", `statement lists uncertified component '${c.type}'`);
    if (cert!.subject.pub !== c.pub) {
      fail("COMPONENT_NOT_TRUSTED", `statement's '${c.type}' key does not match its certificate`);
    }
  }
  for (const t of certByType.keys()) {
    if (!claimTypes.has(t)) fail("COMPONENT_NOT_TRUSTED", `certified component '${t}' missing from statement`);
  }

  // ---- 7. Per-component live signature ----------------------------------
  const transcript = await statementTranscriptHash(statement);
  for (const claim of statement.components) {
    const cert = certByType.get(claim.type);
    if (!cert) fail("COMPONENT_NOT_TRUSTED", `no certificate for component '${claim.type}'`);
    const pub = await importEd25519Public(b64uDecode(cert!.subject.pub));
    if (!(await ed25519Verify(pub, transcript, b64uDecode(claim.challengeSig)))) {
      fail("COMPONENT_ATTESTATION_INVALID", `component '${claim.type}' failed live challenge`, {
        component: claim.type,
      });
    }
  }

  // ---- 8. Policy -------------------------------------------------------
  const modelPolicy = findPolicy(policy, certModel);
  if (!modelPolicy) fail("POLICY_VIOLATION", `no policy for model '${certModel}'`);
  const mp = modelPolicy!;
  if (now - CLOCK_SKEW > mp.notAfter) fail("ALLOWLIST_EXPIRED", "policy bundle expired; update the app");
  if (now + CLOCK_SKEW < mp.issuedAt) fail("ALLOWLIST_EXPIRED", "policy bundle not yet valid");
  if (mp.policyVersion < inputs.minPolicyVersion) {
    fail("POLICY_VIOLATION", "policy bundle is older than the last accepted version (rollback)");
  }
  if (mp.revokedSerials.includes(certSerial)) {
    fail("DEVICE_REVOKED", "this device serial has been revoked by the factory");
  }
  if (mp.revokedKeyIds.includes(seKid)) {
    fail("KEY_REVOKED", "attestation key revoked");
  }
  for (const t of Object.keys(componentKidByType)) {
    if (mp.revokedKeyIds.includes(componentKidByType[t]!)) {
      fail("KEY_REVOKED", `component key '${t}' revoked`);
    }
  }
  // Component set must exactly equal the required set for this model.
  const required = new Set(mp.requiredComponents);
  for (const t of required) {
    if (!claimTypes.has(t)) fail("BOM_INCOMPLETE", `required component '${t}' not attested`);
  }
  for (const t of claimTypes) {
    if (!required.has(t)) fail("POLICY_VIOLATION", `component '${t}' not allowed for this model`);
  }
  // Firmware must be a known, approved image with matching digest.
  const fw = matchFirmware(mp, statement.firmware.version, statement.firmware.digest);
  if (!fw) fail("FIRMWARE_NOT_ALLOWED", "firmware digest/version is not in the approved list");
  if (!fw!.approved) fail("FIRMWARE_NOT_ALLOWED", "this firmware build is not approved for asset operations");
  if (statement.firmware.secureVersion < fw!.secureVersion) {
    fail("SECURE_VERSION_TOO_LOW", "device secure version is lower than the approved image requires");
  }
  // Per-component firmware digests must be approved too.
  for (const claim of statement.components) {
    if (!mp.firmware.some((f) => f.approved && f.digest === claim.fwDigest)) {
      fail("FIRMWARE_NOT_ALLOWED", `component '${claim.type}' firmware digest is not approved`, {
        component: claim.type,
      });
    }
  }

  // ---- 9. Rollback against pinned state ---------------------------------
  // Resolve the pin from the *verified* serial and identity, never from an
  // unauthenticated hint.  `inputs.pinned` is honoured only for callers that
  // already know the serial out-of-band (tests); the manager uses resolvePin.
  const pinned = inputs.pinned ?? inputs.resolvePin?.(certSerial);
  if (inputs.pinned && inputs.pinned.attestationPub !== certPub) {
    // A caller-supplied pin for the wrong device must not silently apply to a
    // different one; require the identity to match before trusting it.
    fail("DEVICE_MISMATCH", "the supplied pin does not belong to this device");
  }
  let firstSight = true;
  if (pinned) {
    firstSight = false;
    if (pinned.attestationPub !== certPub) {
      fail("DEVICE_MISMATCH", "attestation public key differs from the pin");
    }
    if (pinned.bomDigest !== certBom) {
      fail("DEVICE_MISMATCH", "BOM digest differs from the pin");
    }
    if (pinned.batch !== statement.batch) {
      fail("DEVICE_MISMATCH", "batch id differs from the pin");
    }
    for (const [t, prevKid] of Object.entries(pinned.componentKids)) {
      if (componentKidByType[t] !== prevKid) {
        fail("BOM_DIGEST_MISMATCH", `component '${t}' key differs from the pin`);
      }
    }
    if (statement.seCounter < pinned.seCounter) {
      fail("COUNTER_ROLLBACK", "SE counter regressed vs. the pin");
    }
    for (const [t, prev] of Object.entries(pinned.bootCounters)) {
      const got = statement.components.find((c) => c.type === t)?.bootCounter ?? 0;
      if (got < prev) fail("COUNTER_ROLLBACK", `component '${t}' boot counter regressed vs. the pin`);
    }
    if (statement.firmware.secureVersion < pinned.secureVersion) {
      fail("FIRMWARE_ROLLBACK", "secure version regressed vs. the pin");
    }
    // Policy-version monotonicity for THIS device: the bundle applied now must
    // not be older than the one last applied to this serial.  Without this, a
    // rolled-back policy bundle (older revocations / firmware approvals) could
    // re-admit a device even though the global `minPolicyVersion` gate passed.
    if (mp.policyVersion < pinned.policyVersion) {
      fail("POLICY_VIOLATION", "policy bundle is older than the version last applied to this device");
    }
  }

  // ---- 10. Assemble result ---------------------------------------------
  const bootCounters: Record<string, number> = {};
  for (const c of statement.components) bootCounters[c.type] = c.bootCounter;

  const device: TrustedDevice = {
    serial: certSerial,
    model: certModel,
    batch: statement.batch,
    attestationKid: seKid,
    attestationPub: certPub,
    bomDigest: certBom,
    componentPubs: componentPubByType,
    componentKids: componentKidByType,
    seCounter: statement.seCounter,
    bootCounters,
    firmware: {
      version: statement.firmware.version,
      digest: statement.firmware.digest,
      secureVersion: statement.firmware.secureVersion,
    },
    policyVersion: mp.policyVersion,
    statement,
    certs: chain.chain,
  };

  return {
    ok: true,
    device,
    firstSight,
    userPresenceRequired: inputs.requireUserPresence,
  };
}

/**
 * Verify the policy bundle's signature and that its issuer chains to the root.
 * `issuerCerts` is the leaf-first policy bundle (policy leaf + CA cert).
 */
export async function verifyPolicyBundleChain(
  policy: PolicyBundle,
  issuerCerts: ReadonlyArray<unknown>,
  root: TrustRoot,
  now: number,
  verifySig: (policy: PolicyBundle, issuer: Awaited<ReturnType<typeof importEd25519Public>>) => Promise<boolean>,
): Promise<void> {
  const chain = await verifyChain(issuerCerts, root, { now, clockSkewSec: CLOCK_SKEW });
  const leaf = chain.leaf;
  requireRole(leaf, "policy", "policy issuer certificate");
  const kid = b64u(await sha256(b64uDecode(leaf.subject.pub)));
  if (kid !== policy.issuerKid) {
    fail("ALLOWLIST_SIGNATURE_INVALID", "policy bundle issuer does not match the policy certificate");
  }
  const issuerPub = await importEd25519Public(b64uDecode(leaf.subject.pub));
  if (!(await verifySig(policy, issuerPub))) {
    fail("ALLOWLIST_SIGNATURE_INVALID", "policy bundle signature is invalid");
  }
}

export type { ComponentType };
