import test from "node:test";
import assert from "node:assert/strict";

import { DeviceManager } from "../src/manager/device-manager.ts";
import { makeDevice, makeFixture, policyBundleOf, firmwareDigest } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice, type DeviceState } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../src/transport/loopback.ts";
import type { SealedBlob, StorageSecret } from "../src/trust/store.ts";
import { b64u } from "../src/util/bytes.ts";

const storage: StorageSecret = { secret: new Uint8Array(32).fill(0x99), context: "test-profile" };

interface Rig {
  manager: DeviceManager;
  fx: Awaited<ReturnType<typeof makeFixture>>;
  material: Awaited<ReturnType<typeof makeDevice>>;
  policy: Awaited<ReturnType<typeof policyBundleOf>>;
  fw: { version: string; digest: string; secureVersion: number };
  stored: SealedBlob | null;
}

async function rig(nowOffset = 0, serial = "AUR0001XYZ"): Promise<Rig> {
  const fx = await makeFixture();
  const material = await makeDevice(fx, serial);
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const r: Rig = { manager: null as never, fx, material, policy, fw, stored: null };
  r.manager = new DeviceManager({
    root: { root: fx.root.root.public },
    policy,
    policyIssuerCerts: [fx.policyIssuer.cert, fx.ca.cert],
    storage,
    now: () => fx.now + nowOffset,
    persist: async (blob) => { r.stored = blob; },
  });
  await r.manager.init(null);
  return r;
}

function transportFor(state: DeviceState) {
  return loopbackTransport(simulatedResponder(new SimulatedDevice(state)));
}

function stateFor(r: Rig, seCounter = 100, bootCounters = { se: 100, mcu: 50, display: 30, flash: 20 }): DeviceState {
  return genuineDevice(r.material, r.fw, seCounter, bootCounters);
}

test("manager: first connect authenticates and pins the device", async () => {
  const r = await rig();
  const verdict = await r.manager.checkDevice(transportFor(stateFor(r)));
  assert.equal(verdict.kind, "authentic-but-unpinned");
  assert.ok(r.stored, "state was persisted");
  assert.equal(r.manager.listPinned().length, 1);
});

test("manager: subsequent use reports fully genuine", async () => {
  const r = await rig();
  await r.manager.checkDevice(transportFor(stateFor(r)));
  const verdict = await r.manager.checkDevice(transportFor(stateFor(r, 120, { se: 120, mcu: 55, display: 33, flash: 22 })));
  assert.equal(verdict.kind, "genuine");
});

test("manager: a swapped component on a later use is rejected and breaks nothing", async () => {
  const r = await rig();
  await r.manager.checkDevice(transportFor(stateFor(r)));
  const evil = { ...stateFor(r), components: stateFor(r).components.map((c) => c.type === "mcu" ? { ...c, willSign: false } : c) };
  const verdict = await r.manager.checkDevice(transportFor(evil));
  assert.equal(verdict.kind, "rejected");
  if (verdict.kind === "rejected") {
    assert.ok(verdict.code === "COMPONENT_ATTESTATION_INVALID" || verdict.code === "BOM_DIGEST_MISMATCH");
  }
});

test("manager: state survives a restart (sealed blob reloaded)", async () => {
  const r = await rig();
  await r.manager.checkDevice(transportFor(stateFor(r)));
  const blob = r.stored!;

  // New process, same storage secret, reload the blob.
  const r2: Rig = { ...r, stored: blob };
  r2.manager = new DeviceManager({
    root: { root: r.fx.root.root.public },
    policy: r.policy,
    policyIssuerCerts: [r.fx.policyIssuer.cert, r.fx.ca.cert],
    storage,
    now: () => r.fx.now,
    persist: async (b) => { r2.stored = b; },
  });
  await r2.manager.init(blob);
  const verdict = await r2.manager.checkDevice(transportFor(stateFor(r, 110, { se: 110, mcu: 50, display: 30, flash: 20 })));
  assert.equal(verdict.kind, "genuine");
});

test("manager: after restart, a counter rollback is caught", async () => {
  const r = await rig();
  await r.manager.checkDevice(transportFor(stateFor(r, 500, { se: 500, mcu: 90, display: 60, flash: 40 })));
  const blob = r.stored!;

  const r2: Rig = { ...r };
  r2.manager = new DeviceManager({
    root: { root: r.fx.root.root.public },
    policy: r.policy,
    policyIssuerCerts: [r.fx.policyIssuer.cert, r.fx.ca.cert],
    storage,
    now: () => r.fx.now,
    persist: async (b) => { r2.stored = b; },
  });
  await r2.manager.init(blob);
  // The device now reports lower counters -> a rollback attack.
  const verdict = await r2.manager.checkDevice(transportFor(stateFor(r, 100, { se: 100, mcu: 50, display: 30, flash: 20 })));
  assert.equal(verdict.kind, "rejected");
  if (verdict.kind === "rejected") assert.equal(verdict.code, "COUNTER_ROLLBACK");
});

test("manager: a corrupt policy bundle is rejected at init", async () => {
  const fx = await makeFixture();
  const policy = await policyBundleOf(fx);
  const tampered = { ...policy, policies: policy.policies.map((p) => ({ ...p, policyVersion: 999 })) };
  const m = new DeviceManager({
    root: { root: fx.root.root.public },
    policy: tampered,
    policyIssuerCerts: [fx.policyIssuer.cert, fx.ca.cert],
    storage,
    now: () => fx.now,
    persist: async () => {},
  });
  await assert.rejects(() => m.init(null), /policy|signature/i);
});

test("manager: presence confirmation runs for a genuine session", async () => {
  const r = await rig();
  const verdict = await r.manager.checkDevice(transportFor(stateFor(r)));
  if (verdict.kind === "rejected") throw new Error("setup failed");
  const session = verdict.session;

  // Simulate the device's button press + signed response.
  const { presenceSigningBytes } = await import("../src/manager/presence.ts");
  const result = await r.manager.confirmPresence(session, async (challenge) => {
    const body = {
      v: 1 as const, kind: "presence-response" as const,
      presenceNonce: challenge.presenceNonce, pressed: true, displayCode: challenge.displayCode,
    };
    const sig = await r.material.attestation.sign(presenceSigningBytes(challenge, body));
    return { ...body, sig: b64u(sig) };
  });
  assert.deepEqual(result, { ok: true });
});

test("manager: presence without a press is refused", async () => {
  const r = await rig();
  const verdict = await r.manager.checkDevice(transportFor(stateFor(r)));
  if (verdict.kind === "rejected") throw new Error("setup failed");
  const result = await r.manager.confirmPresence(verdict.session, async (challenge) => {
    const { presenceSigningBytes } = await import("../src/manager/presence.ts");
    const body = {
      v: 1 as const, kind: "presence-response" as const,
      presenceNonce: challenge.presenceNonce, pressed: false, displayCode: challenge.displayCode,
    };
    const sig = await r.material.attestation.sign(presenceSigningBytes(challenge, body));
    return { ...body, sig: b64u(sig) };
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, "USER_PRESENCE_REQUIRED");
});
