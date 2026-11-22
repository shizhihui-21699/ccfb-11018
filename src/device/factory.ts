/**
 * Factory provisioning: creates a root CA, a device CA, and per-device key
 * material + certificates, then exports a bundle for the host app to ship.
 *
 * This module is used by the *factory tool* and by tests.  It is NOT part of
 * the host runtime; the host only ever holds the root public key.  Keeping it
 * in a separate directory makes that boundary auditable: nothing under
 * `manager/` or `attestation/` imports from here.
 *
 * Trust hierarchy (offline-verifiable, shipped as a tiny root-only anchor):
 *
 *   root  (self-signed; public key baked into the desktop app)
 *    └─ device-ca (intermediate)
 *        ├─ attestation cert  (SE attestation key; carries serial/model/bomDigest)
 *        └─ component certs   (SE*, MCU, display, flash — each its own key)
 *
 *   (*) The SE's attestation key doubles as the "se" component key so the BOM
 *       digest covers it.  Documented explicitly to avoid a subtle gap.
 *
 *   policy bundle is signed by a dedicated `policy` key under the device-ca.
 */

import {
  generateEd25519Signer,
  exportEd25519Pkcs8,
  importEd25519Public,
  type Ed25519Signer,
  type Ed25519PublicKey,
} from "../crypto/primitives.ts";
import { b64u, type Bytes } from "../util/bytes.ts";
import { fail } from "../util/errors.ts";
import {
  issueCert,
  type CertRole,
  type Certificate,
  type ComponentType,
} from "../trust/certs.ts";
import {
  computeBomDigest,
  issuePolicyBundle,
  type BomEntry,
  type ModelPolicy,
  type PolicyBundle,
} from "../trust/policy.ts";

export interface RootMaterial {
  readonly root: Ed25519Signer;
}

export interface DeviceCaMaterial {
  readonly ca: Ed25519Signer;
  readonly cert: Certificate;
}

export interface ComponentKey {
  readonly type: ComponentType;
  readonly signer: Ed25519Signer;
  readonly cert: Certificate;
}

export interface DeviceMaterial {
  readonly serial: string;
  readonly model: string;
  readonly batch: string;
  readonly attestation: Ed25519Signer;
  readonly attestationCert: Certificate;
  readonly components: ReadonlyArray<ComponentKey>;
  readonly bomDigest: string;
  /** Leaf-first certificate bundle as the device would present it. */
  readonly certBundle: ReadonlyArray<Certificate>;
}

const DAY = 86400;

export async function createRoot(): Promise<RootMaterial> {
  const root = await generateEd25519Signer();
  return { root };
}

/** The root's own trust anchor representation shipped in the app. */
export function rootAnchorPublic(root: RootMaterial): Ed25519PublicKey {
  return root.root.public;
}

export async function createDeviceCa(root: RootMaterial, now: number): Promise<DeviceCaMaterial> {
  const ca = await generateEd25519Signer();
  const cert = await issueCert(
    root.root,
    { pub: b64u(ca.public.raw), role: "device-ca" },
    { issuedAt: now - DAY, notAfter: now + 10 * 365 * DAY },
  );
  return { ca, cert };
}

export interface ProvisionOptions {
  readonly serial: string;
  readonly model: string;
  readonly batch: string;
  readonly now: number;
  /** Component types the factory installs in this model. */
  readonly components: ReadonlyArray<ComponentType>;
  /** Validity window for the leaf certs. */
  readonly certValidityDays?: number;
}

/**
 * Provision one device: generate fresh per-component keys, compute the BOM
 * digest over the full set (SE included), issue the attestation cert carrying
 * that digest, and assemble the leaf-first certificate bundle.
 */
export async function provisionDevice(
  _root: RootMaterial,
  ca: DeviceCaMaterial,
  opts: ProvisionOptions,
): Promise<DeviceMaterial> {
  const validityDays = opts.certValidityDays ?? 5 * 365;
  const notAfter = opts.now + validityDays * DAY;

  // The attestation key IS the SE key.  Generate all component keys first.
  const componentSigners = new Map<ComponentType, Ed25519Signer>();
  for (const t of opts.components) {
    if (componentSigners.has(t)) fail("INTERNAL_ERROR", `provision: duplicate component ${t}`);
    componentSigners.set(t, await generateEd25519Signer());
  }
  const seSigner = componentSigners.get("se");
  if (!seSigner) fail("INTERNAL_ERROR", "provision: model must include an 'se' component");

  // BOM over the installed set.
  const bomEntries: BomEntry[] = [];
  for (const [type, signer] of componentSigners) {
    bomEntries.push({ type, pub: b64u(signer.public.raw) });
  }
  const bomDigestBytes = await computeBomDigest(bomEntries);
  const bomDigest = b64u(bomDigestBytes);

  // Attestation cert (issued by device-ca), carrying serial/model/bomDigest.
  // This cert *is* the SE's identity: the SE has exactly one certificate, in
  // the attestation role, and no separate component cert.  That avoids two
  // certificates claiming the same subject key.
  const attestationCert = await issueCert(
    ca.ca,
    {
      pub: b64u(seSigner.public.raw),
      role: "attestation",
      serial: opts.serial,
      model: opts.model,
      bomDigest,
    },
    { issuedAt: opts.now - DAY, notAfter },
  );

  // Component certs bound to serial + model.  The SE is covered by its
  // attestation cert above, so we only issue certs for the other components.
  const components: ComponentKey[] = [];
  for (const [type, signer] of componentSigners) {
    if (type === "se") {
      components.push({ type, signer, cert: attestationCert });
      continue;
    }
    const cert = await issueCert(
      ca.ca,
      { pub: b64u(signer.public.raw), role: "component", type, serial: opts.serial, model: opts.model },
      { issuedAt: opts.now - DAY, notAfter },
    );
    components.push({ type, signer, cert });
  }
  // Deterministic ordering by component type for stable bundling.
  components.sort((a, b) => (a.type < b.type ? -1 : 1));

  // Leaf-first bundle: attestation, each non-SE component cert, then the CA
  // cert.  The SE's component entry above reuses the attestation cert, which is
  // already in the bundle, so it is not added twice.
  const certBundle: Certificate[] = [
    attestationCert,
    ...components.filter((c) => c.type !== "se").map((c) => c.cert),
    ca.cert,
  ];

  return {
    serial: opts.serial,
    model: opts.model,
    batch: opts.batch,
    attestation: seSigner,
    attestationCert,
    components,
    bomDigest,
    certBundle,
  };
}

// ---------------------------------------------------------------------------
// Policy issuer (factory "the approved firmware list")
// ---------------------------------------------------------------------------

export interface PolicyIssuer {
  readonly signer: Ed25519Signer;
  readonly cert: Certificate;
}

export async function createPolicyIssuer(_root: RootMaterial, ca: DeviceCaMaterial, now: number): Promise<PolicyIssuer> {
  const signer = await generateEd25519Signer();
  const cert = await issueCert(
    ca.ca,
    { pub: b64u(signer.public.raw), role: "policy" },
    { issuedAt: now - DAY, notAfter: now + 5 * 365 * DAY },
  );
  // The policy cert is itself signed by the CA; the root pins the CA through
  // the device chain.  We include the CA cert and policy cert in a small
  // bundle the host verifies once.
  return { signer, cert };
}

export async function issuePolicy(
  issuer: PolicyIssuer,
  policies: ReadonlyArray<ModelPolicy>,
): Promise<PolicyBundle> {
  return issuePolicyBundle(issuer.signer, policies);
}

/** Convenience: a policy cert bundle (policy leaf + CA cert) for the host. */
export function policyBundleCerts(issuer: PolicyIssuer, ca: DeviceCaMaterial): Certificate[] {
  return [issuer.cert, ca.cert];
}

export interface RootBundle {
  /** base64url raw Ed25519 public key of the root. */
  readonly rootPub: string;
  /** CA cert (signed by root) for chain building. */
  readonly caCert: Certificate;
}

export function encodeRootBundle(root: RootMaterial, ca: DeviceCaMaterial): RootBundle {
  return { rootPub: b64u(root.root.public.raw), caCert: ca.cert };
}

/** The desktop app ships exactly this: one root public key. */
export async function loadPinnedRoot(rootPubB64: string): Promise<Ed25519PublicKey> {
  return importEd25519Public((await import("../util/bytes.ts")).b64uDecode(rootPubB64));
}

export { exportEd25519Pkcs8 };
export type { Ed25519Signer, Ed25519PublicKey, Bytes };
export type { CertRole };
