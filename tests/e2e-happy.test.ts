import test from "node:test";
import assert from "node:assert/strict";

import { makeDevice, makeFixture, policyBundleOf } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../src/transport/loopback.ts";
import { runVerification, describeFailure } from "../src/manager/verify.ts";
import { verifyPolicyBundleChain } from "../src/attestation/verifier.ts";
import { verifyPolicyBundle } from "../src/trust/policy.ts";
import { firmwareDigest } from "../src/device/fixture.ts";

async function setup() {
  const fx = await makeFixture();
  const material = await makeDevice(fx, "AUR0001XYZ");
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 100, { se: 100, mcu: 50, display: 30, flash: 20 });
  const device = new SimulatedDevice(state);
  return { fx, material, policy, fw, device };
}

test("happy path: genuine device verifies end to end", async () => {
  const { fx, policy, device } = await setup();
  const transport = loopbackTransport(simulatedResponder(device));

  let sasSeen = "";
  const session = await runVerification({
    transport,
    root: { root: fx.root.root.public },
    policy,
    minPolicyVersion: 0,
    now: fx.now,
    onSas: (s) => { sasSeen = s; },
  });

  assert.equal(session.device.serial, "AUR0001XYZ");
  assert.equal(session.device.model, fx.policy.model);
  assert.equal(session.device.firmware.version, "1.4.2");
  assert.equal(session.device.seCounter, 100);
  assert.equal(session.firstSight, true);
  assert.match(session.sas, /^\d{4} \d{4} \d{4} \d{4} \d{4}$/);
  assert.equal(sasSeen, session.sas);
  assert.ok(session.userPresenceRequired === false);
});

test("session MAC helpers work", async () => {
  const { fx, policy, device } = await setup();
  const transport = loopbackTransport(simulatedResponder(device));
  const session = await runVerification({
    transport, root: { root: fx.root.root.public }, policy, minPolicyVersion: 0, now: fx.now,
  });
  const pt = new TextEncoder().encode("get-xpub");
  const mac = await session.macHostCommand(1, pt);
  assert.equal(mac.length, 32);
});

test("policy bundle signature verifies against its issuer", async () => {
  const fx = await makeFixture();
  const policy = await policyBundleOf(fx);
  // The policy leaf is signed by the CA; the CA chains to the root.
  const issuerLeafCert = policy.issuerKid;

  // Verify via chain: policy bundle + [policy cert, ca cert].
  let called = false;
  await verifyPolicyBundleChain(
    policy,
    [fx.policyIssuer.cert, fx.ca.cert],
    { root: fx.root.root.public },
    fx.now,
    async (b, issuer) => {
      called = true;
      assert.equal(issuer.kid, issuerLeafCert);
      return verifyPolicyBundle(b, issuer);
    },
  );
  assert.ok(called, "policy signature callback ran");
});

test("certificate chain rejects an expired leaf", async () => {
  const fx = await makeFixture();
  const material = await makeDevice(fx, "AUR0001EXP", { certValidityDays: 1 });
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 1);
  const transport = loopbackTransport(simulatedResponder(new SimulatedDevice(state)));

  // Verify 10 days later -> cert (valid 1 day) is expired.
  let err: unknown;
  try {
    await runVerification({
      transport, root: { root: fx.root.root.public }, policy, minPolicyVersion: 0,
      now: fx.now + 10 * 86400,
    });
  } catch (e) {
    err = e;
  }
  const d = describeFailure(err);
  assert.equal(d.code, "CERT_EXPIRED");
});
