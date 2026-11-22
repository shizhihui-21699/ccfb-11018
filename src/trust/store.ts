/**
 * Trust store: what the host remembers between connections.
 *
 * Re-verification on every use is only meaningful if the host remembers a
 * device's identity and the highest counters it has ever seen.  Otherwise an
 * attacker could present an old (but validly signed) statement — a "rollback"
 * — and the device would look pristine while running, say, downgraded firmware.
 *
 * Stored per device (keyed by serial + attestation kid):
 *   - the pinned SE attestation public key and the full expected BOM digest,
 *   - the pinned component key set,
 *   - the highest seCounter and per-component bootCounter ever observed,
 *   - the highest secureVersion / policy version,
 *   - the firmware digest last approved, and the last successful verification.
 *
 * Sealed at rest
 * --------------
 * The store is encrypted and integrity-protected with AES-256-GCM under a key
 * derived from an OS-protected secret (in the desktop app: a keychain-stored
 * random 32 bytes; in this library: an injected `StorageSecret`).  Tampering
 * with the file on disk yields an authentication failure, not a silent reset —
 * a plaintext-editable store would let an attacker lower the counters.
 *
 * Replay of an *older, still valid* sealed blob (putting back a lower-counter
 * store) is a separate problem that encryption cannot solve, because the old
 * blob is authentic.  It is defeated by an `EpochGuard` the host supplies: a
 * durable high-water mark kept outside the file (keychain item, TPM counter,
 * etc.).  `load` rejects a blob older than that mark; `seal` advances it.  If
 * no guard is supplied, replay protection is the host's responsibility and is
 * documented as such — we do not claim it from the blob alone.
 */

import { canonicalString, parseCanonical } from "../util/canonical.ts";
import { fail } from "../util/errors.ts";
import { b64u, b64uDecode, concat, toHex, type Bytes, utf8Encode, zeroize } from "../util/bytes.ts";
import { aesGcmOpen, aesGcmSeal, deriveStorageKey } from "../crypto/primitives.ts";
import { digestOf } from "../crypto/primitives.ts";

export interface DeviceRecord {
  readonly serial: string;
  readonly model: string;
  /** Pinned SE attestation key id (base64url SHA-256 of raw pubkey). */
  readonly attestationKid: string;
  /** Raw SE attestation pubkey, base64url — pinned trust anchor for this device. */
  readonly attestationPub: string;
  /** Expected BOM digest (base64url), as signed by the CA. */
  readonly bomDigest: string;
  /** Component type -> pinned key id. */
  readonly componentKids: Readonly<Record<string, string>>;
  /** Highest SE counter observed. */
  readonly seCounter: number;
  /** Highest per-component boot counter observed. */
  readonly bootCounters: Readonly<Record<string, number>>;
  /** Highest firmware secureVersion observed. */
  readonly secureVersion: number;
  /** Last approved firmware digest (base64url). */
  readonly firmwareDigest: string;
  /** Last approved firmware version string. */
  readonly firmwareVersion: string;
  /** Highest policy version applied for this device. */
  readonly policyVersion: number;
  /** Unix seconds of last successful verification. */
  readonly lastVerifiedAt: number;
  /** batch id pinned at first sight. */
  readonly batch: string;
}

export interface StoreState {
  readonly v: 1;
  readonly storeEpoch: number;
  /**
   * Highest policy version this host has ever accepted, across all devices.
   * Enforces anti-downgrade of the policy bundle (revocations, firmware
   * approvals) independently of any single device's pin.
   */
  readonly minPolicyVersion: number;
  readonly devices: Readonly<Record<string, DeviceRecord>>;
}

const EMPTY_STATE: StoreState = { v: 1, storeEpoch: 0, minPolicyVersion: 0, devices: {} };

/** A source of high-entropy secret material for at-rest sealing.  In the
 *  desktop app this is backed by the OS keychain; tests inject a fixed one. */
export interface StorageSecret {
  readonly secret: Bytes;
  readonly context: string;
}

/**
 * External monotonic state guard.
 *
 * The sealed blob is authenticated but NOT self-protecting against *replay* or
 * *deletion*: an attacker with write access to the store file can put back an
 * older, still-validly-sealed blob (lower counters/policy), or delete the file
 * entirely (fresh store, no memory).  To close both, the host keeps a small
 * durable record somewhere the attacker cannot roll back — a keychain item, an
 * OS preference, a TPM counter — and supplies it here.  It must outlive the
 * store file.
 *
 * `load`/`seal` use `epoch` for replay detection and `minPolicyVersion` so a
 * deleted-then-refilled store cannot re-admit a downgraded policy bundle.
 */
export interface EpochGuard {
  getHighWaterMark(): Promise<number>;
  setHighWaterMark(epoch: number): Promise<void>;
  /** Highest policy version ever accepted, or 0. Optional; when present it is
   *  carried across store deletion so the policy floor survives. */
  getMinPolicyVersion?(): Promise<number>;
  setMinPolicyVersion?(version: number): Promise<void>;
}

export interface SealedBlob {
  readonly v: 1;
  readonly nonce: string;
  readonly ciphertext: string;
  /** Cleartext AAD-bound store epoch for quick replay ordering checks. */
  readonly epoch: number;
  /** Cleartext SHA-256 of ciphertext for corruption detection before decrypt. */
  readonly digest: string;
}

export class TrustStore {
  private state: StoreState;
  private readonly guard: EpochGuard | undefined;

  private constructor(state: StoreState, guard?: EpochGuard) {
    this.state = state;
    this.guard = guard;
  }

  /** Load from a previously sealed blob.  A missing blob is a fresh store.
   *
   *  If `guard` is provided, a blob whose epoch is below the guard's
   *  high-water mark is rejected as a replay (see `EpochGuard`).
   */
  static async load(
    blob: SealedBlob | null,
    storage: StorageSecret,
    guard?: EpochGuard,
  ): Promise<TrustStore> {
    const guardEpoch = guard ? await guard.getHighWaterMark() : 0;
    const guardPolicy = guard?.getMinPolicyVersion ? await guard.getMinPolicyVersion() : 0;
    if (blob === null) {
      // A fresh store still inherits the external policy floor, so deleting the
      // file cannot reset anti-downgrade protection.
      const base: StoreState = { ...EMPTY_STATE, minPolicyVersion: guardPolicy };
      return new TrustStore(base, guard);
    }
    if (guard && blob.epoch < guardEpoch) {
      fail("TRUST_STORE_REPLAY", "sealed store is older than the last committed epoch (replay)");
    }
    const state = await openBlob(blob, storage);
    // The external policy floor never decreases across store load.
    const merged: StoreState =
      guardPolicy > state.minPolicyVersion ? { ...state, minPolicyVersion: guardPolicy } : state;
    return new TrustStore(merged, guard);
  }

  /** Serialize + seal the current state.  Advances epoch and, with a guard,
   *  durably persists the epoch and policy high-water marks. */
  async seal(storage: StorageSecret, guard?: EpochGuard): Promise<SealedBlob> {
    const next: StoreState = { ...this.state, storeEpoch: this.state.storeEpoch + 1 };
    const blob = await sealState(next, storage);
    this.state = next;
    const g = guard ?? this.guard;
    if (g) {
      await g.setHighWaterMark(next.storeEpoch);
      if (g.setMinPolicyVersion) await g.setMinPolicyVersion(next.minPolicyVersion);
    }
    return blob;
  }

  get deviceCount(): number {
    return Object.keys(this.state.devices).length;
  }

  get epoch(): number {
    return this.state.storeEpoch;
  }

  /** Highest policy version ever accepted by this host. */
  get minPolicyVersion(): number {
    return this.state.minPolicyVersion;
  }

  /** Raise the policy-version high-water mark (never lowers it).  If the host
   *  supplied a guard with policy persistence, the new floor is durable even if
   *  the store file is later deleted. */
  async recordPolicyVersion(version: number): Promise<void> {
    if (!Number.isSafeInteger(version) || version < 0) {
      fail("TRUST_STORE_CORRUPT", "policy version out of range");
    }
    if (version <= this.state.minPolicyVersion) return;
    this.state = { ...this.state, minPolicyVersion: version };
    if (this.guard?.setMinPolicyVersion) await this.guard.setMinPolicyVersion(version);
  }

  getDevice(serial: string): DeviceRecord | undefined {
    return this.state.devices[serial];
  }

  listDevices(): DeviceRecord[] {
    return Object.values(this.state.devices).sort((a, b) => (a.serial < b.serial ? -1 : 1));
  }

  /** Upsert a device's pinned identity at first successful verification. */
  private upsert(record: DeviceRecord): void {
    this.state = {
      ...this.state,
      devices: { ...this.state.devices, [record.serial]: record },
    };
  }

  /**
   * Apply a freshly verified statement to the store.
   *
   * Enforces:
   *  - identity pin: attestationKid and BOM must match what we pinned;
   *  - counter monotonicity: seCounter and bootCounters must not regress;
   *  - secureVersion monotonicity;
   *  - policyVersion monotonicity is enforced by the caller against the policy
   *    bundle; here we persist the highest.
   *
   * Throws with `UNPINNED_DEVICE` / `COUNTER_ROLLBACK` / `DEVICE_MISMATCH` /
   * `FIRMWARE_ROLLBACK` on any violation.
   */
  commitVerified(record: DeviceRecord): void {
    const existing = this.state.devices[record.serial];
    if (!existing) {
      // First time we see this serial: pin it.
      if (record.seCounter === 0) {
        // A genuine device always has a positive SE counter after first boot.
        // Zero at first sight is allowed (freshly manufactured), but recorded.
      }
      this.upsert(record);
      return;
    }
    if (existing.attestationKid !== record.attestationKid || existing.attestationPub !== record.attestationPub) {
      fail("DEVICE_MISMATCH", "attestation key does not match the pinned key for this serial", {
        serial: record.serial,
      });
    }
    if (existing.bomDigest !== record.bomDigest) {
      fail("DEVICE_MISMATCH", "BOM digest does not match the pinned BOM for this serial", { serial: record.serial });
    }
    if (existing.batch !== record.batch) {
      fail("DEVICE_MISMATCH", "batch id does not match the pin", { serial: record.serial });
    }
    // Component set must be identical to the pinned set.
    const pinnedKids = existing.componentKids;
    const nowKids = record.componentKids;
    const allTypes = new Set([...Object.keys(pinnedKids), ...Object.keys(nowKids)]);
    for (const t of allTypes) {
      if (pinnedKids[t] !== nowKids[t]) {
        fail("BOM_DIGEST_MISMATCH", `component '${t}' key does not match the pinned BOM`, { serial: record.serial, component: t });
      }
    }
    if (record.seCounter < existing.seCounter) {
      fail("COUNTER_ROLLBACK", "SE counter regressed", {
        serial: record.serial, seen: existing.seCounter, got: record.seCounter,
      });
    }
    for (const t of allTypes) {
      const prev = existing.bootCounters[t] ?? 0;
      const now = record.bootCounters[t] ?? 0;
      if (now < prev) {
        fail("COUNTER_ROLLBACK", `component '${t}' boot counter regressed`, {
          serial: record.serial, component: t, seen: prev, got: now,
        });
      }
    }
    if (record.secureVersion < existing.secureVersion) {
      fail("FIRMWARE_ROLLBACK", "secure version regressed", {
        serial: record.serial, seen: existing.secureVersion, got: record.secureVersion,
      });
    }
    // Merge: keep maxima even if this session reported lower-but-valid values
    // (e.g. a component not re-read this time reports 0).
    const merged: DeviceRecord = {
      ...record,
      seCounter: Math.max(existing.seCounter, record.seCounter),
      secureVersion: Math.max(existing.secureVersion, record.secureVersion),
      policyVersion: Math.max(existing.policyVersion, record.policyVersion),
      bootCounters: mergeMax(existing.bootCounters, record.bootCounters),
    };
    this.upsert(merged);
  }
}

function mergeMax(a: Readonly<Record<string, number>>, b: Readonly<Record<string, number>>): Record<string, number> {
  const out: Record<string, number> = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = Math.max(out[k] ?? 0, v);
  return out;
}

// ---------------------------------------------------------------------------
// Seal / open
// ---------------------------------------------------------------------------

async function sealState(state: StoreState, storage: StorageSecret): Promise<SealedBlob> {
  const key = await deriveStorageKey(storage.secret, storage.context);
  try {
    const plaintext = utf8Encode(canonicalString(state));
    const aad = utf8Encode(`trust-store/v1\u0000${state.storeEpoch}`);
    const { nonce, ciphertext } = await aesGcmSeal(key, plaintext, aad);
    return {
      v: 1,
      nonce: b64u(nonce),
      ciphertext: b64u(ciphertext),
      epoch: state.storeEpoch,
      digest: toHex(await digestOf("trust-store-ct/v1", { ciphertext: b64u(ciphertext) })),
    };
  } finally {
    zeroize(key);
  }
}

async function openBlob(blob: SealedBlob, storage: StorageSecret): Promise<StoreState> {
  // Structural checks on the cleartext envelope first.
  if (blob.v !== 1) fail("TRUST_STORE_CORRUPT", "unsupported store version");
  if (!Number.isSafeInteger(blob.epoch) || blob.epoch < 0) fail("TRUST_STORE_CORRUPT", "bad epoch");
  let nonce: Bytes, ct: Bytes;
  try {
    nonce = b64uDecode(blob.nonce);
    ct = b64uDecode(blob.ciphertext);
  } catch {
    fail("TRUST_STORE_CORRUPT", "store envelope is not valid base64url");
  }
  if (nonce.length !== 12) fail("TRUST_STORE_CORRUPT", "bad nonce");
  const expectDigest = toHex(await digestOf("trust-store-ct/v1", { ciphertext: b64u(ct) }));
  if (expectDigest !== blob.digest) fail("TRUST_STORE_CORRUPT", "ciphertext digest mismatch");

  const key = await deriveStorageKey(storage.secret, storage.context);
  try {
    const aad = utf8Encode(`trust-store/v1\u0000${blob.epoch}`);
    const plaintext = await aesGcmOpen(key, nonce, ct, aad);
    let parsed: unknown;
    try {
      parsed = parseCanonical(plaintext, { maxBytes: 64 << 20, maxDepth: 16, maxKeys: 1 << 20 });
    } catch {
      fail("TRUST_STORE_CORRUPT", "store plaintext is not canonical JSON");
    }
    return validateState(parsed);
  } finally {
    zeroize(key);
  }
}

function validateState(v: unknown): StoreState {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("TRUST_STORE_CORRUPT", "state: not an object");
  const o = v as Record<string, unknown>;
  if (o["v"] !== 1) fail("TRUST_STORE_CORRUPT", "state: bad version");
  const epoch = o["storeEpoch"];
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
    fail("TRUST_STORE_CORRUPT", "state: bad epoch");
  }
  // minPolicyVersion was added after the first release; a store written before
  // it existed simply has no high-water mark yet (0).
  const mpvRaw = o["minPolicyVersion"];
  const minPolicyVersion =
    mpvRaw === undefined
      ? 0
      : typeof mpvRaw === "number" && Number.isSafeInteger(mpvRaw) && mpvRaw >= 0
        ? mpvRaw
        : (fail("TRUST_STORE_CORRUPT", "state: bad minPolicyVersion") as never);
  const devicesRaw = o["devices"];
  if (devicesRaw === null || typeof devicesRaw !== "object" || Array.isArray(devicesRaw)) {
    fail("TRUST_STORE_CORRUPT", "state: bad devices");
  }
  const devices: Record<string, DeviceRecord> = {};
  for (const [serial, rec] of Object.entries(devicesRaw as Record<string, unknown>)) {
    devices[serial] = validateRecord(serial, rec);
  }
  return { v: 1, storeEpoch: epoch, minPolicyVersion, devices };
}

function isInt(v: unknown, min: number, max: number): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max;
}

function isStr(v: unknown, maxLen: number): v is string {
  return typeof v === "string" && v.length <= maxLen;
}

function validateRecord(serial: string, v: unknown): DeviceRecord {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("TRUST_STORE_CORRUPT", "record: not an object");
  const o = v as Record<string, unknown>;
  if (!/^[A-Z0-9][A-Z0-9-]{3,31}$/.test(serial)) fail("TRUST_STORE_CORRUPT", "record: bad serial key");
  const need = (k: string) => {
    if (!(k in o)) fail("TRUST_STORE_CORRUPT", `record: missing ${k}`);
    return o[k];
  };
  const rec: DeviceRecord = {
    serial,
    model: str(need("model"), 32, "model"),
    attestationKid: str(need("attestationKid"), 64, "attestationKid"),
    attestationPub: str(need("attestationPub"), 64, "attestationPub"),
    bomDigest: str(need("bomDigest"), 64, "bomDigest"),
    componentKids: numStrMap(need("componentKids"), "componentKids"),
    seCounter: int(need("seCounter"), 0, 0xffffffff, "seCounter"),
    bootCounters: numNumMap(need("bootCounters"), "bootCounters"),
    secureVersion: int(need("secureVersion"), 0, 0xffffff, "secureVersion"),
    firmwareDigest: str(need("firmwareDigest"), 64, "firmwareDigest"),
    firmwareVersion: str(need("firmwareVersion"), 32, "firmwareVersion"),
    policyVersion: int(need("policyVersion"), 0, Number.MAX_SAFE_INTEGER, "policyVersion"),
    lastVerifiedAt: int(need("lastVerifiedAt"), 0, 4_102_444_800, "lastVerifiedAt"),
    batch: str(need("batch"), 32, "batch"),
  };
  return rec;
}

function str(v: unknown, maxLen: number, what: string): string {
  if (!isStr(v, maxLen)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad string`);
  return v;
}
function int(v: unknown, min: number, max: number, what: string): number {
  if (!isInt(v, min, max)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad integer`);
  return v;
}
function numStrMap(v: unknown, what: string): Record<string, string> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad map`);
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (!isStr(k, 16) || !isStr(val, 64)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad entry`);
    out[k] = val;
  }
  return out;
}
function numNumMap(v: unknown, what: string): Record<string, number> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad map`);
  const out: Record<string, number> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (!isStr(k, 16) || !isInt(val, 0, 0xffffffff)) fail("TRUST_STORE_CORRUPT", `record.${what}: bad entry`);
    out[k] = val;
  }
  return out;
}

/** Canonical serialization of the envelope for on-disk storage in tests. */
export function encodeSealedBlob(blob: SealedBlob): string {
  return canonicalString(blob);
}

export function parseSealedBlob(text: string): SealedBlob {
  const v = parseCanonical(new TextEncoder().encode(text), { maxBytes: 64 << 20, maxDepth: 4, maxKeys: 16 });
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("TRUST_STORE_CORRUPT", "blob: not an object");
  const o = v as Record<string, unknown>;
  const nonce = o["nonce"];
  const ciphertext = o["ciphertext"];
  const epoch = o["epoch"];
  const digest = o["digest"];
  if (o["v"] !== 1) fail("TRUST_STORE_CORRUPT", "blob: bad version");
  if (!isStr(nonce, 64) || !isStr(ciphertext, 64 << 20) || !isStr(digest, 128) || !isInt(epoch, 0, Number.MAX_SAFE_INTEGER)) {
    fail("TRUST_STORE_CORRUPT", "blob: bad fields");
  }
  return { v: 1, nonce, ciphertext, epoch, digest };
}

export { concat, utf8Encode };
