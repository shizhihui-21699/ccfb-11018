import test from "node:test";
import assert from "node:assert/strict";

import {
  TrustStore,
  encodeSealedBlob,
  parseSealedBlob,
  type DeviceRecord,
  type SealedBlob,
  type StorageSecret,
} from "../src/trust/store.ts";
import { b64u } from "../src/util/bytes.ts";
import { describeFailure } from "../src/manager/verify.ts";

const storage: StorageSecret = { secret: new Uint8Array(32).fill(0x42), context: "test-host" };

function record(over: Partial<DeviceRecord> = {}): DeviceRecord {
  return {
    serial: "AUR0001XYZ",
    model: "AURUM-X1",
    attestationKid: "kid-se",
    attestationPub: b64u(new Uint8Array(32).fill(1)),
    bomDigest: b64u(new Uint8Array(32).fill(2)),
    componentKids: { se: "kid-se", mcu: "kid-mcu", display: "kid-disp", flash: "kid-flash" },
    seCounter: 100,
    bootCounters: { se: 100, mcu: 50, display: 30, flash: 20 },
    secureVersion: 7,
    firmwareDigest: b64u(new Uint8Array(32).fill(3)),
    firmwareVersion: "1.4.2",
    policyVersion: 12,
    lastVerifiedAt: 1_780_000_000,
    batch: "B2026Q1",
    ...over,
  };
}

test("store: seals and reopens with the same secret", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const blob = await s.seal(storage);
  const s2 = await TrustStore.load(blob, storage);
  assert.equal(s2.deviceCount, 1);
  assert.equal(s2.getDevice("AUR0001XYZ")?.seCounter, 100);
});

test("store: a different secret cannot open the blob", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const blob = await s.seal(storage);
  const wrong: StorageSecret = { secret: new Uint8Array(32).fill(0x43), context: "test-host" };
  await assert.rejects(() => TrustStore.load(blob, wrong), /decryption|seal/i);
});

test("store: tampering with ciphertext is detected", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const blob = await s.seal(storage);
  const ct = blob.ciphertext;
  const mutated = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
  const bad: SealedBlob = { ...blob, ciphertext: mutated };
  let err: unknown;
  try {
    await TrustStore.load(bad, storage);
  } catch (e) {
    err = e;
  }
  assert.equal(describeFailure(err).code, "TRUST_STORE_CORRUPT");
});

test("store: tampering the cleartext epoch invalidates the AAD", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const blob = await s.seal(storage);
  const bad: SealedBlob = { ...blob, epoch: blob.epoch + 1 };
  let err: unknown;
  try {
    await TrustStore.load(bad, storage);
  } catch (e) {
    err = e;
  }
  assert.ok(
    describeFailure(err).code === "TRUST_STORE_SEAL_INVALID" || describeFailure(err).code === "TRUST_STORE_CORRUPT",
    `expected seal/corrupt, got ${describeFailure(err).code}`,
  );
});

test("store: counter regression is refused at commit time", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record({ seCounter: 500 }));
  assert.throws(() => s.commitVerified(record({ seCounter: 400 })), /regressed|COUNTER_ROLLBACK|SE counter/i);
});

test("store: component key change is refused at commit time", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const changed = record({
    componentKids: { se: "kid-se", mcu: "kid-EVIL", display: "kid-disp", flash: "kid-flash" },
  });
  assert.throws(() => s.commitVerified(changed), /component|BOM/i);
});

test("store: attestation key change is refused at commit time", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  assert.throws(() => s.commitVerified(record({ attestationPub: b64u(new Uint8Array(32).fill(9)) })), /pin|mismatch|attestation/i);
});

test("store: a component reporting 0 after a higher value is a rollback", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record({ seCounter: 500, bootCounters: { se: 500, mcu: 80, display: 30, flash: 20 } }));
  // A genuine device always reports true monotonic counters; 0 is a regression.
  assert.throws(
    () => s.commitVerified(record({ seCounter: 500, bootCounters: { se: 500, mcu: 0, display: 40, flash: 20 } })),
    /regressed|COUNTER_ROLLBACK/i,
  );
});

test("store: equal or higher counters advance the record", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record({ seCounter: 500, bootCounters: { se: 500, mcu: 80, display: 30, flash: 20 } }));
  s.commitVerified(record({ seCounter: 600, bootCounters: { se: 600, mcu: 90, display: 40, flash: 25 } }));
  const rec = s.getDevice("AUR0001XYZ")!;
  assert.equal(rec.seCounter, 600);
  assert.equal(rec.bootCounters["mcu"], 90);
  assert.equal(rec.bootCounters["display"], 40);
});

test("store: encode/parse round-trip of the sealed envelope", async () => {
  const s = await TrustStore.load(null, storage);
  s.commitVerified(record());
  const blob = await s.seal(storage);
  const text = encodeSealedBlob(blob);
  const parsed = parseSealedBlob(text);
  assert.deepEqual(parsed, blob);
  const reopened = await TrustStore.load(parsed, storage);
  assert.equal(reopened.deviceCount, 1);
});
