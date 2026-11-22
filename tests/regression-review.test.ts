/**
 * Regression tests for vulnerabilities found in adversarial review.
 * Each test would have passed against a vulnerable build; keeping them here
 * ensures the fixes cannot silently regress.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { makeFixture, makeDevice, policyBundleOf, firmwareDigest } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice, type DeviceState } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../src/transport/loopback.ts";
import { runVerification, describeFailure } from "../src/manager/verify.ts";
import { DeviceManager } from "../src/manager/device-manager.ts";
import { TrustStore, type EpochGuard, type DeviceRecord, type SealedBlob } from "../src/trust/store.ts";
import { issueCert } from "../src/trust/certs.ts";
import { computeBomDigest } from "../src/trust/policy.ts";
import { issuePolicy } from "../src/device/factory.ts";
import { generateEd25519Signer } from "../src/crypto/primitives.ts";
import { b64u } from "../src/util/bytes.ts";

async function base() {
  const fx = await makeFixture();
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const material = await makeDevice(fx, "AUR0001REV");
  const state = genuineDevice(material, fw, 100);
  return { fx, policy, fw, material, state };
}

// #1 — issuer role (also covered in the attack suite; kept here as the canonical
// regression).  A component key must not be usable as a CA.
test("REGRESSION #1: a certified component key cannot issue an attestation cert", async () => {
  const b = await base();
  const mcu = b.material.components.find((c) => c.type === "mcu")!;
  const fakeSe = await generateEd25519Signer();
  const bom = await computeBomDigest([
    { type: "se", pub: b64u(fakeSe.public.raw) },
    ...b.material.components.filter((c) => c.type !== "se").map((c) => ({ type: c.type, pub: b64u(c.signer.public.raw) })),
  ]);
  const fakeAtt = await issueCert(
    mcu.signer,
    { pub: b64u(fakeSe.public.raw), role: "attestation", serial: "AUR0001REV", model: "AURUM-X1", bomDigest: b64u(bom) },
    { issuedAt: b.fx.now - 86400, notAfter: b.fx.now + 365 * 86400 },
  );
  const evil: DeviceState = {
    ...b.state,
    material: { ...b.material, attestation: fakeSe },
    components: [
      { type: "se", signer: fakeSe, bootCounter: 100, fwDigest: b.fw.digest, willSign: true },
      ...b.state.components.filter((c) => c.type !== "se"),
    ],
    certBundleOverride: [fakeAtt, mcu.cert, ...b.material.components.filter((c) => c.type !== "se" && c.type !== "mcu").map((c) => c.cert), b.fx.ca.cert] as unknown[],
  };
  let err: unknown;
  try {
    await runVerification({
      transport: loopbackTransport(simulatedResponder(new SimulatedDevice(evil))),
      root: { root: b.fx.root.root.public }, policy: b.policy, minPolicyVersion: 0, now: b.fx.now, timeoutMs: 2000,
    });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "CERT_KEY_USAGE");
});

// #2 — policy bundle downgrade across app restarts.
test("REGRESSION #2: an older policy bundle is rejected after a newer one was accepted", async () => {
  const b = await base();
  const storage = { secret: new Uint8Array(32).fill(2), context: "reg2" };
  const revoked = await issuePolicy(b.fx.policyIssuer, [{ ...b.fx.policy, policyVersion: 13, revokedSerials: ["AUR0001REV"] }]);
  const stale = await issuePolicy(b.fx.policyIssuer, [{ ...b.fx.policy, policyVersion: 12 }]);
  let saved: SealedBlob | null = null;
  // A guard backed by plain variables, simulating keychain storage.
  let hwm = 0;
  let floor = 0;
  const guard: EpochGuard = {
    getHighWaterMark: async () => hwm, setHighWaterMark: async (e) => { hwm = e; },
    getMinPolicyVersion: async () => floor, setMinPolicyVersion: async (v) => { floor = v; },
  };

  const m1 = new DeviceManager({
    root: { root: b.fx.root.root.public }, policy: revoked, policyIssuerCerts: [b.fx.policyIssuer.cert, b.fx.ca.cert],
    storage, now: () => b.fx.now, persist: async (blob) => { saved = blob; }, epochGuard: guard,
  });
  await m1.init(null);

  const m2 = new DeviceManager({
    root: { root: b.fx.root.root.public }, policy: stale, policyIssuerCerts: [b.fx.policyIssuer.cert, b.fx.ca.cert],
    storage, now: () => b.fx.now, persist: async () => {}, epochGuard: guard,
  });
  await assert.rejects(() => m2.init(saved), (e: unknown) => describeFailure(e).code === "POLICY_VIOLATION");
});

test("REGRESSION #2b: deleting the store file cannot reset the policy floor when a guard is used", async () => {
  const b = await base();
  const storage = { secret: new Uint8Array(32).fill(21), context: "reg2b" };
  const revoked = await issuePolicy(b.fx.policyIssuer, [{ ...b.fx.policy, policyVersion: 13, revokedSerials: ["AUR0001REV"] }]);
  const stale = await issuePolicy(b.fx.policyIssuer, [{ ...b.fx.policy, policyVersion: 12 }]);
  let hwm = 0;
  let floor = 0;
  const guard: EpochGuard = {
    getHighWaterMark: async () => hwm, setHighWaterMark: async (e) => { hwm = e; },
    getMinPolicyVersion: async () => floor, setMinPolicyVersion: async (v) => { floor = v; },
  };
  const m1 = new DeviceManager({
    root: { root: b.fx.root.root.public }, policy: revoked, policyIssuerCerts: [b.fx.policyIssuer.cert, b.fx.ca.cert],
    storage, now: () => b.fx.now, persist: async () => {}, epochGuard: guard,
  });
  await m1.init(null);
  // Attacker DELETES the store (init(null)) and feeds the older bundle.
  const m2 = new DeviceManager({
    root: { root: b.fx.root.root.public }, policy: stale, policyIssuerCerts: [b.fx.policyIssuer.cert, b.fx.ca.cert],
    storage, now: () => b.fx.now, persist: async () => {}, epochGuard: guard,
  });
  await assert.rejects(() => m2.init(null), (e: unknown) => describeFailure(e).code === "POLICY_VIOLATION");
});

// #3 — per-device policy-version rollback vs the pin.
test("REGRESSION #3: a policy bundle older than the device's pin is rejected", async () => {
  const b = await base();
  // Pin the device at policyVersion 20.
  const pinned = {
    attestationPub: b.material.attestationCert.subject.pub,
    bomDigest: b.material.bomDigest,
    batch: b.material.batch,
    componentKids: Object.fromEntries(b.state.components.map((c) => [c.type, c.signer.public.kid])),
    seCounter: 100, bootCounters: { se: 1, mcu: 1, display: 1, flash: 1 },
    secureVersion: 7, policyVersion: 20,
  };
  let err: unknown;
  try {
    await runVerification({
      transport: loopbackTransport(simulatedResponder(new SimulatedDevice(b.state))),
      root: { root: b.fx.root.root.public }, policy: b.policy, minPolicyVersion: 0, now: b.fx.now,
      pinned, timeoutMs: 2000,
    });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "POLICY_VIOLATION");
});

// #4 — sealed store replay past the external high-water mark.
test("REGRESSION #4: replaying an older sealed store is rejected by the epoch guard", async () => {
  const storage = { secret: new Uint8Array(32).fill(4), context: "reg4" };
  let hwm = 0;
  const guard: EpochGuard = { getHighWaterMark: async () => hwm, setHighWaterMark: async (e) => { hwm = e; } };
  const rec = (se: number): DeviceRecord => ({
    serial: "AUR0001REV", model: "AURUM-X1", attestationKid: "k",
    attestationPub: b64u(new Uint8Array(32).fill(1)), bomDigest: b64u(new Uint8Array(32).fill(2)),
    componentKids: { se: "se" }, seCounter: se, bootCounters: { se }, secureVersion: 7,
    firmwareDigest: b64u(new Uint8Array(32).fill(3)), firmwareVersion: "1.4.2", policyVersion: 1,
    lastVerifiedAt: 1000, batch: "B",
  });
  const s = await TrustStore.load(null, storage, guard);
  s.commitVerified(rec(500));
  const oldBlob = await s.seal(storage, guard);
  s.commitVerified(rec(900));
  await s.seal(storage, guard);

  await assert.rejects(
    () => TrustStore.load(oldBlob, storage, guard),
    (e: unknown) => describeFailure(e).code === "TRUST_STORE_REPLAY",
  );
});

// #5 — SAS acknowledgment wired into checkDevice.
test("REGRESSION #5: a failed SAS acknowledgment yields RELAY_SUSPECTED", async () => {
  const b = await base();
  const m = new DeviceManager({
    root: { root: b.fx.root.root.public }, policy: b.policy, policyIssuerCerts: [b.fx.policyIssuer.cert, b.fx.ca.cert],
    storage: { secret: new Uint8Array(32).fill(5), context: "reg5" }, now: () => b.fx.now,
    persist: async () => {}, acknowledgeSas: async () => false,
  });
  await m.init(null);
  const verdict = await m.checkDevice(loopbackTransport(simulatedResponder(new SimulatedDevice(b.state))));
  assert.equal(verdict.kind, "rejected");
  if (verdict.kind === "rejected") assert.equal(verdict.code, "RELAY_SUSPECTED");
});

// #6 — a caller-supplied pin for a different device must not apply silently.
test("REGRESSION #6: a pin that belongs to a different device is refused", async () => {
  const b = await base();
  const wrongPin = {
    attestationPub: b64u(new Uint8Array(32).fill(99)), // not this device's key
    bomDigest: b.material.bomDigest, batch: b.material.batch,
    componentKids: {}, seCounter: 0, bootCounters: {}, secureVersion: 0, policyVersion: 0,
  };
  let err: unknown;
  try {
    await runVerification({
      transport: loopbackTransport(simulatedResponder(new SimulatedDevice(b.state))),
      root: { root: b.fx.root.root.public }, policy: b.policy, minPolicyVersion: 0, now: b.fx.now,
      pinned: wrongPin, timeoutMs: 2000,
    });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "DEVICE_MISMATCH");
});

test("REGRESSION #6b: the pin resolver receives the VERIFIED serial, not a wire hint", async () => {
  const b = await base();
  let seenSerial = "";
  const transport = loopbackTransport(simulatedResponder(new SimulatedDevice(b.state)));
  await runVerification({
    transport, root: { root: b.fx.root.root.public }, policy: b.policy, minPolicyVersion: 0, now: b.fx.now,
    timeoutMs: 2000,
    resolvePin: (serial) => { seenSerial = serial; return undefined; },
  });
  assert.equal(seenSerial, b.material.serial, "resolver must be given the certificate-bound serial");
});
