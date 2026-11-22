/**
 * DeviceManager — the single entry point the desktop companion app uses.
 *
 * It composes the three pillars into the two flows the product needs:
 *
 *   checkDevice()   — "is this the genuine device?"  Called on first connect
 *                     and on every subsequent use.  Runs the full handshake,
 *                     verifies offline, pins/compares against the trust store,
 *                     and returns a verdict the UI can act on.
 *
 *   confirmPresence() — the physical step for high-value operations.  Proves a
 *                     human is holding the device right now (anti-relay), bound
 *                     to this session.
 *
 * Nothing here talks to the network.  Nothing here reads wallet secrets.  The
 * `DeviceTransport` is injected so the same manager drives real hardware or the
 * simulator.
 *
 * Verdicts are a closed set; the UI must render them literally and must never
 * downgrade a non-`genuine` verdict to "proceed anyway" on its own.
 */

import type { Ed25519PublicKey } from "../crypto/primitives.ts";
import { canonicalString } from "../util/canonical.ts";
import { describeFailure, runVerification, type DeviceTransport, type Session } from "./verify.ts";
import {
  makePresenceChallenge,
  verifyPresence,
  deriveDisplayCode,
  type PresenceChallenge,
  type PresenceResponse,
} from "./presence.ts";
import { TrustStore, type DeviceRecord, type EpochGuard, type SealedBlob, type StorageSecret } from "../trust/store.ts";
import { verifyPolicyBundleChain } from "../attestation/verifier.ts";
import type { PinnedState } from "../attestation/verifier.ts";
import { verifyPolicyBundle, type PolicyBundle } from "../trust/policy.ts";
import type { TrustRoot } from "../trust/certs.ts";
import { statementTranscriptHash } from "../attestation/statement.ts";
import { fail, type ErrorCode } from "../util/errors.ts";
import { randomBytes, type Bytes } from "../util/bytes.ts";

/** The closed set of outcomes the UI renders. */
export type Verdict =
  | { readonly kind: "genuine"; readonly session: Session; readonly serial: string; readonly model: string }
  | { readonly kind: "authentic-but-unpinned"; readonly session: Session; readonly serial: string; readonly model: string }
  | { readonly kind: "rejected"; readonly code: ErrorCode; readonly reason: string; readonly detail?: unknown };

export interface ManagerConfig {
  readonly root: TrustRoot;
  readonly policy: PolicyBundle;
  /** Certs that vouch for the policy bundle (policy leaf + CA). */
  readonly policyIssuerCerts: ReadonlyArray<unknown>;
  readonly storage: StorageSecret;
  /** Provide the current time in seconds (injectable for tests). */
  readonly now: () => number;
  /** Persist a sealed blob (caller owns the file/OS keychain binding). */
  readonly persist: (blob: SealedBlob) => Promise<void>;
  /**
   * Durable high-water mark kept outside the sealed blob, so an older blob
   * cannot be replayed to lower counters/policy.  See `EpochGuard`.  Strongly
   * recommended; without it, store replay protection is the host's job.
   */
  readonly epochGuard?: EpochGuard;
  /**
   * If set, `checkDevice` requires the SAS to be acknowledged as matching
   * before returning `genuine` (anti-relay).  The `acknowledgeSas` callback is
   * expected to show `sas` to the user and resolve true only if the device's
   * own screen showed the same code.  This wires the documented relay defence
   * into the main flow rather than leaving it to the caller.
   */
  readonly acknowledgeSas?: (sas: string) => Promise<boolean>;
}

export class DeviceManager {
  private store: TrustStore | null = null;
  private readonly config: ManagerConfig;
  private policyVersion = 0;

  constructor(config: ManagerConfig) {
    this.config = config;
  }

  /** Load the trust store and verify the offline policy bundle. Must be called
   *  once before `checkDevice`. */
  async init(sealed: SealedBlob | null): Promise<void> {
    // 1. The policy bundle must be authentic before we trust any of its claims.
    await verifyPolicyBundleChain(
      this.config.policy,
      this.config.policyIssuerCerts,
      this.config.root,
      this.config.now(),
      verifyPolicyBundle,
    );
    // 2. Load device pins (with replay guard if supplied).
    this.store = await TrustStore.load(sealed, this.config.storage, this.config.epochGuard);
    // 3. Anti-downgrade: the bundle's version must not be below the highest we
    //    have ever accepted (persisted globally, not per-device).  Compute the
    //    effective minimum BEFORE assigning this.policyVersion.
    const bundleMax = Math.max(...this.config.policy.policies.map((p) => p.policyVersion));
    const floor = Math.max(this.store.minPolicyVersion, bundleMax);
    if (bundleMax < this.store.minPolicyVersion) {
      fail("POLICY_VIOLATION", "this policy bundle is older than one already accepted on this computer");
    }
    this.policyVersion = floor;
    await this.store.recordPolicyVersion(bundleMax);
    await this.config.persist(await this.store.seal(this.config.storage, this.config.epochGuard));
  }

  private requireStore(): TrustStore {
    if (!this.store) throw new Error("DeviceManager.init() must be called first");
    return this.store;
  }

  /**
   * First-connect and every-use check.
   *
   * `transport` is an open byte channel to the device.  Returns a `Verdict`;
   * never throws for device-side attacks (it converts them to `rejected`), so
   * the UI has one shape to handle.  Programming errors (manager not inited)
   * still throw.
   */
  async checkDevice(transport: DeviceTransport, opts?: { requireUserPresence?: boolean }): Promise<Verdict> {
    const store = this.requireStore();
    const now = this.config.now();

    // The host does not know which device is attached until the statement
    // arrives, so we hand the orchestrator a pin *resolver*.  It looks up the
    // serial from the (still unverified) statement to choose the pin, then the
    // full verifier re-parses and validates everything — a lying serial can only
    // cause a lookup miss, never a wrong verdict.
    let session: Session;
    try {
      session = await runVerification({
        transport,
        root: this.config.root,
        policy: this.config.policy,
        minPolicyVersion: this.policyVersion,
        now,
        requireUserPresence: opts?.requireUserPresence ?? false,
        resolvePin: (serial) => {
          const rec = store.getDevice(serial);
          return rec ? pinFromRecord(rec) : undefined;
        },
      });
    } catch (e) {
      const f = describeFailure(e);
      return { kind: "rejected", code: f.code, reason: f.message, detail: f.detail };
    }

    // Commit the advanced state (pin on first sight, or update maxima).
    const record = recordFromSession(session, now);
    try {
      store.commitVerified(record);
    } catch (e) {
      const f = describeFailure(e);
      return { kind: "rejected", code: f.code, reason: f.message, detail: f.detail };
    }
    await this.config.persist(await store.seal(this.config.storage, this.config.epochGuard));

    // Anti-relay gate: if the host configured an SAS acknowledgement, require it
    // before we call the device "genuine".  A transparent relay to a remote
    // genuine device passes every cryptographic check but shows a *different*
    // SAS on the device's own screen, which the user will report as a mismatch.
    if (this.config.acknowledgeSas) {
      let matched = false;
      try {
        matched = await this.config.acknowledgeSas(session.sas);
      } catch {
        matched = false;
      }
      if (!matched) {
        return {
          kind: "rejected",
          code: "RELAY_SUSPECTED",
          reason: "the code shown on the device did not match this computer's code",
        };
      }
    }

    return {
      kind: session.firstSight ? "authentic-but-unpinned" : "genuine",
      session,
      serial: record.serial,
      model: record.model,
    };
  }

  /**
   * The physical presence step for high-value operations.
   *
   * `press` is supplied by the transport layer: it sends the challenge to the
   * device and awaits the user pressing the button, returning the device's
   * signed response.  In the simulator this is scripted; on real hardware it
   * blocks on the device's button.
   */
  async confirmPresence(
    session: Session,
    press: (challenge: PresenceChallenge) => Promise<PresenceResponse>,
  ): Promise<{ ok: true } | { ok: false; code: ErrorCode; reason: string }> {
    const transcript = await statementTranscriptHash(session.device.statement);
    const challenge = await makePresenceChallenge(session, transcript, randomBytes(24));
    let response: PresenceResponse;
    try {
      response = await press(challenge);
    } catch (e) {
      const f = describeFailure(e);
      return { ok: false, code: f.code, reason: f.message };
    }
    try {
      await verifyPresence({ challenge, response, device: session.device, expectedTranscriptHash: transcript });
      return { ok: true };
    } catch (e) {
      const f = describeFailure(e);
      return { ok: false, code: f.code, reason: f.message };
    }
  }

  /** The display code the device shows for a presence challenge (simulator
   *  uses this; on real hardware the device renders it itself). */
  static displayCodeFor(challenge: PresenceChallenge): string {
    return challenge.displayCode;
  }

  /** Expose the pinned devices (for a management UI). */
  listPinned(): DeviceRecord[] {
    return this.requireStore().listDevices();
  }
}

export { deriveDisplayCode, canonicalString };
export type { PresenceChallenge, PresenceResponse, DeviceRecord, SealedBlob, Ed25519PublicKey, Bytes };

// ---------------------------------------------------------------------------
// Record <-> pin conversion
// ---------------------------------------------------------------------------

function recordFromSession(session: Session, now: number): DeviceRecord {
  return {
    serial: session.device.serial,
    model: session.device.model,
    attestationKid: session.device.attestationKid,
    attestationPub: session.device.attestationPub,
    bomDigest: session.device.bomDigest,
    componentKids: session.device.componentKids,
    seCounter: session.device.seCounter,
    bootCounters: session.device.bootCounters,
    secureVersion: session.device.firmware.secureVersion,
    firmwareDigest: session.device.firmware.digest,
    firmwareVersion: session.device.firmware.version,
    policyVersion: session.device.policyVersion,
    lastVerifiedAt: now,
    batch: session.device.batch,
  };
}

function pinFromRecord(rec: DeviceRecord): PinnedState {
  return {
    attestationPub: rec.attestationPub,
    bomDigest: rec.bomDigest,
    batch: rec.batch,
    componentKids: rec.componentKids,
    seCounter: rec.seCounter,
    bootCounters: rec.bootCounters,
    secureVersion: rec.secureVersion,
    policyVersion: rec.policyVersion,
  };
}
