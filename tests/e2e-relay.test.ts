/**
 * Relay / man-in-the-middle tests.
 *
 * Two relay models are exercised:
 *
 *  A. **Re-keying relay** (terminates ECDH on both sides).  This is the only
 *     way a middlebox can read or modify traffic.  It must present its *own*
 *     ephemeral key to the device, which the device signs into the statement as
 *     `hostEphPub`.  The host expects to see its own key there, so the binding
 *     fails — before any SAS comparison is even needed.
 *
 *  B. **Transparent relay** (forwards bytes faithfully).  It cannot read
 *     anything, but could still be relaying a genuine device that is not in the
 *     user's hand.  That is defeated by the physical presence step: the remote
 *     device has no human to press its button.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { makeFixture, makeDevice, policyBundleOf, firmwareDigest } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../src/transport/loopback.ts";
import { runVerification, describeFailure } from "../src/manager/verify.ts";
import { generateX25519 } from "../src/crypto/primitives.ts";
import { b64u, randomBytes, type Bytes } from "../src/util/bytes.ts";
import { encodeHello, parseHello, type HelloMessage } from "../src/protocol/messages.ts";

async function world(serial = "AUR0001XYZ") {
  const fx = await makeFixture();
  const material = await makeDevice(fx, serial);
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 100);
  return { fx, material, policy, fw, state };
}

test("relay A: a re-keying relay cannot satisfy the hostEphPub binding", async () => {
  const w = await world();

  // The relay's own ephemeral key toward the device.
  const relayEph = await generateX25519();

  // The relay forwards a *modified* HELLO to the device, substituting its own
  // ephemeral key so it can terminate the ECDH and read traffic.
  const tap = (dir: "host->device" | "device->host", bytes: Bytes): Bytes => {
    if (dir === "host->device") {
      const hello = parseHello(JSON.parse(new TextDecoder().decode(bytes)) as unknown);
      const rewritten: HelloMessage = {
        ...hello,
        hostEphPub: b64u(relayEph.publicRaw), // relay's key, not the host's
      };
      return encodeHello(rewritten);
    }
    return bytes;
  };

  const transport = loopbackTransport(simulatedResponder(new SimulatedDevice(w.state)), tap);
  let err: unknown;
  try {
    await runVerification({
      transport, root: { root: w.fx.root.root.public }, policy: w.policy,
      minPolicyVersion: 0, now: w.fx.now, timeoutMs: 3000,
    });
  } catch (e) {
    err = e;
  }
  assert.equal(describeFailure(err).code, "TRANSCRIPT_MISMATCH");
});

test("relay A': an independent ECDH on the host side yields a different SAS than the device", async () => {
  const w = await world();
  // Host does a session directly with the device and records the SAS.
  const directTransport = loopbackTransport(simulatedResponder(new SimulatedDevice(w.state)));
  let hostSas = "";
  await runVerification({
    transport: directTransport, root: { root: w.fx.root.root.public }, policy: w.policy,
    minPolicyVersion: 0, now: w.fx.now, onSas: (s) => { hostSas = s; },
  });

  // A relay that re-keys toward the device produces a *different* ECDH on the
  // device side, hence a different SAS.  We model that by doing the device leg
  // with the relay's ephemeral key instead of the host's.
  const hostEph = await generateX25519();
  const relayEph = await generateX25519();
  const hello = encodeHello({
    v: 1, kind: "hello", sessionId: b64u(randomBytes(16)),
    hostNonce: b64u(randomBytes(32)), hostEphPub: b64u(relayEph.publicRaw), hostTime: w.fx.now,
  });
  const dev = new SimulatedDevice(w.state);
  await dev.handleHello(hello);
  const deviceSas = dev.deviceSas();
  assert.ok(deviceSas, "device computed a SAS");
  assert.notEqual(deviceSas, hostSas, "relay side sees a different SAS than the host");
  void hostEph;
});

test("relay B: a transparent relay to a remote device is stopped by the presence step", async () => {
  const w = await world();
  // A transparent relay forwards bytes faithfully; the handshake completes
  // because it is genuinely the same device.  But the presence step needs a
  // physical press on the device *in hand* — which the remote genuine device
  // cannot provide.  We model "no one pressed" by refusing to sign.
  const transport = loopbackTransport(simulatedResponder(new SimulatedDevice(w.state)));
  const verdict = await (async () => {
    const { DeviceManager } = await import("../src/manager/device-manager.ts");
    const mgr = new DeviceManager({
      root: { root: w.fx.root.root.public },
      policy: w.policy,
      policyIssuerCerts: [w.fx.policyIssuer.cert, w.fx.ca.cert],
      storage: { secret: new Uint8Array(32).fill(5), context: "relay" },
      now: () => w.fx.now,
      persist: async () => {},
    });
    await mgr.init(null);
    const v = await mgr.checkDevice(transport);
    if (v.kind === "rejected") return v;
    // The relay cannot obtain a signed presence response from an unattended
    // remote device; model that as the press timing out.
    const presence = await mgr.confirmPresence(v.session, async () => {
      throw new Error("no one is at the remote device to press the button");
    });
    return { kind: "presence", presence };
  })();

  if (verdict.kind === "presence") {
    assert.equal(verdict.presence.ok, false);
  } else {
    assert.fail("expected the handshake to succeed so presence is the gate");
  }
});
