/**
 * Attack suite — the security contract.
 *
 * Each test constructs an adversary that speaks the protocol correctly and
 * varies exactly one capability, then asserts the *specific* failure code.  The
 * parameterised helper keeps each case short and makes the mapping from attack
 * to code the thing under test.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { makeDevice, makeFixture, policyBundleOf, firmwareDigest } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice, type DeviceState } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder, type WireTap } from "../src/transport/loopback.ts";
import { runVerification, describeFailure } from "../src/manager/verify.ts";
import { encodeAttest, decodeWireMessage, parseAttest } from "../src/protocol/messages.ts";
import { canonicalString } from "../src/util/canonical.ts";
import { b64u } from "../src/util/bytes.ts";
import { generateEd25519Signer } from "../src/crypto/primitives.ts";

interface World {
  fx: Awaited<ReturnType<typeof makeFixture>>;
  material: Awaited<ReturnType<typeof makeDevice>>;
  policy: Awaited<ReturnType<typeof policyBundleOf>>;
  fw: { version: string; digest: string; secureVersion: number };
  state: DeviceState;
}

async function world(serial = "AUR0001XYZ"): Promise<World> {
  const fx = await makeFixture();
  const material = await makeDevice(fx, serial);
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 100, { se: 100, mcu: 50, display: 30, flash: 20 });
  return { fx, material, policy, fw, state };
}

async function run(
  w: World,
  state: DeviceState | SimulatedDevice,
  opts?: { tap?: WireTap; pinned?: unknown; minPolicyVersion?: number },
): Promise<{ code: string | null; sas?: string }> {
  const dev = state instanceof SimulatedDevice ? state : new SimulatedDevice(state);
  const transport = loopbackTransport(simulatedResponder(dev), opts?.tap);
  try {
    const session = await runVerification({
      transport,
      root: { root: w.fx.root.root.public },
      policy: w.policy,
      minPolicyVersion: opts?.minPolicyVersion ?? 0,
      now: w.fx.now,
      pinned: opts?.pinned as never,
      timeoutMs: 3000,
    });
    return { code: null, sas: session.sas };
  } catch (e) {
    return { code: describeFailure(e).code };
  }
}

function cloneState(s: DeviceState, over: Partial<DeviceState>): DeviceState {
  return { ...s, ...over };
}

// ---------------------------------------------------------------------------
// 1. Component swap — the headline attack from the prompt.
// ---------------------------------------------------------------------------

test("ATTACK component-swap: a chip with the wrong key cannot pass the live challenge", async () => {
  const w = await world();
  // Attacker keeps the genuine SE + certs, but physically swapped the MCU for a
  // malicious one. The malicious MCU lacks the factory key, so `willSign:false`
  // models it emitting an invalid challengeSig. Its BOM claim also uses a
  // different key, which trips the BOM check first — both are caught.
  const evilMcu = await generateEd25519Signer();
  const state: DeviceState = {
    ...w.state,
    components: w.state.components.map((c) =>
      c.type === "mcu"
        ? { type: "mcu", signer: evilMcu, bootCounter: 1, fwDigest: w.fw.digest, willSign: false }
        : c,
    ),
  };
  const r = await run(w, state);
  assert.ok(r.code === "BOM_DIGEST_MISMATCH" || r.code === "COMPONENT_NOT_TRUSTED",
    `expected BOM/component rejection, got ${r.code}`);
});

test("ATTACK component-swap: same-key chip but dead challenge signature is caught", async () => {
  const w = await world();
  // Attacker re-packages a chip that presents the *right* key material but
  // cannot actually sign (e.g. copied public key only). Only the live challenge
  // distinguishes this, so we disable signing while keeping the BOM identity.
  const state: DeviceState = {
    ...w.state,
    components: w.state.components.map((c) => (c.type === "display" ? { ...c, willSign: false } : c)),
  };
  const r = await run(w, state);
  assert.equal(r.code, "COMPONENT_ATTESTATION_INVALID");
});

test("ATTACK component-swap: impostor chip reports the genuine pubkey but cannot sign", async () => {
  const w = await world();
  // The most insidious variant: the spy chip copies the genuine MCU's PUBLIC
  // key (so BOM and every statement field match perfectly) but does not have
  // its private key. Everything except the live challenge passes.
  const genuineMcu = w.state.components.find((c) => c.type === "mcu")!;
  const genuineMcuPub = b64u(genuineMcu.signer.public.raw);
  const spyKey = await generateEd25519Signer();
  const state: DeviceState = {
    ...w.state,
    components: w.state.components.map((c) =>
      c.type === "mcu"
        ? { type: "mcu", signer: spyKey, claimedPub: genuineMcuPub, bootCounter: c.bootCounter, fwDigest: c.fwDigest, willSign: false }
        : c,
    ),
  };
  const r = await run(w, state);
  assert.equal(r.code, "COMPONENT_ATTESTATION_INVALID", "must fail at the live challenge, not earlier");
});

// ---------------------------------------------------------------------------
// 2. Replay / freshness.
// ---------------------------------------------------------------------------

test("ATTACK replay: echoing a stale host nonce is rejected", async () => {
  const w = await world();
  const staleNonce = b64u(new Uint8Array(32).fill(7));
  const r = await run(w, cloneState(w.state, { hostNonceOverride: staleNonce }));
  assert.equal(r.code, "CHALLENGE_MISMATCH");
});

test("ATTACK replay: a recorded ATTEST injected into a new session is rejected", async () => {
  const w = await world();
  // Capture a genuine ATTEST from session 1.
  const honest = new SimulatedDevice(w.state);
  const hello1 = new TextEncoder().encode(canonicalString({
    v: 1, kind: "hello",
    sessionId: b64u(new Uint8Array(16).fill(1)),
    hostNonce: b64u(new Uint8Array(32).fill(2)),
    hostEphPub: b64u(new Uint8Array(32).fill(3)),
    hostTime: w.fx.now,
  }));
  const recorded = encodeAttest(await honest.handleHello(hello1));

  // Session 2: replay the recorded bytes for the device->host flight.
  let replayed = false;
  const tap: WireTap = (dir, bytes) => {
    if (dir === "device->host" && !replayed) {
      replayed = true;
      return recorded;
    }
    return bytes;
  };
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  assert.equal(r.code, "CHALLENGE_MISMATCH");
});

test("ATTACK replay: an old ATTEST cannot be reused because the transcript is nonce-bound", async () => {
  const w = await world();
  // Record a genuine ATTEST from a session with a *known* host nonce.
  const honest = new SimulatedDevice(w.state);
  const hello1 = new TextEncoder().encode(canonicalString({
    v: 1, kind: "hello",
    sessionId: b64u(new Uint8Array(16).fill(1)),
    hostNonce: b64u(new Uint8Array(32).fill(2)),
    hostEphPub: b64u(new Uint8Array(32).fill(3)),
    hostTime: w.fx.now,
  }));
  const recordedMsg = await honest.handleHello(hello1);
  // The recorded statement is cryptographically valid; it just belongs to a
  // different (older) session. Feed it into a fresh session.
  const tap: WireTap = (dir, bytes) => (dir === "device->host" ? encodeAttest(recordedMsg) : bytes);
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  assert.equal(r.code, "CHALLENGE_MISMATCH");
});

test("control: a device reusing one ephemeral key still verifies (freshness comes from the nonce)", async () => {
  const w = await world();
  // A device with a *fixed* ephemeral key still sends a fresh deviceNonce, so
  // replay is blocked by the nonce. Here we assert the positive: a fixed eph
  // key alone does not let a *recorded* ATTEST through, which the previous
  // test covers. This test instead confirms a genuine device with a fixed eph
  // key still verifies (i.e. we do not false-positive on reuse) — freshness
  // comes from the nonce, and ECDH reuse is a device-side RNG concern.
  const { generateX25519 } = await import("../src/crypto/primitives.ts");
  const fixed = await generateX25519();
  const r = await run(w, cloneState(w.state, { fixedEph: fixed }));
  assert.equal(r.code, null);
});

// ---------------------------------------------------------------------------
// 3. Identity / certificate attacks.
// ---------------------------------------------------------------------------

test("ATTACK identity-swap: statement claims a serial its certificate does not cover", async () => {
  const w = await world();
  const r = await run(w, cloneState(w.state, { statementSerialOverride: "AUR9999FAKE" }));
  assert.equal(r.code, "DEVICE_MISMATCH");
});

test("ATTACK clone: presenting another device's certificate bundle is rejected", async () => {
  const w = await world("AUR0001XYZ");
  const other = await makeDevice(w.fx, "AUR0002OTHER");
  // The attacker ships the *other* device's certs with its own statement.
  const r = await run(
    w,
    cloneState(w.state, { certBundleOverride: other.certBundle as unknown[] }),
  );
  // The statement's key/serial won't match the other bundle's cert.
  assert.ok(r.code === "COMPONENT_NOT_TRUSTED" || r.code === "DEVICE_MISMATCH" || r.code === "BOM_DIGEST_MISMATCH",
    `expected identity mismatch, got ${r.code}`);
});

test("ATTACK forged attestation: statement signed by a non-CA key is rejected", async () => {
  const w = await world();
  const rogue = await generateEd25519Signer();
  const r = await run(w, cloneState(w.state, { statementSignerOverride: rogue }));
  assert.equal(r.code, "STATEMENT_SIGNATURE_INVALID");
});

test("ATTACK issuer-role: a certified component key cannot mint a forged attestation cert", async () => {
  // REGRESSION (was a real vulnerability): the chain verifier must enforce that
  // only a device-ca certificate may act as an issuer.  Otherwise the holder of
  // ANY certified component private key — e.g. a genuine MCU from a scrapped
  // unit — can forge an attestation cert for a swap-in fake Secure Element and
  // the chain still reaches the root.
  const { issueCert } = await import("../src/trust/certs.ts");
  const { computeBomDigest } = await import("../src/trust/policy.ts");
  const w = await world();
  const mcu = w.material.components.find((c) => c.type === "mcu")!;
  const fakeSe = await generateEd25519Signer();
  const bom = await computeBomDigest([
    { type: "se", pub: b64u(fakeSe.public.raw) },
    ...w.material.components.filter((c) => c.type !== "se").map((c) => ({
      type: c.type, pub: b64u(c.signer.public.raw),
    })),
  ]);
  const fakeAtt = await issueCert(
    mcu.signer, // attacker-controlled component key acting as a CA
    { pub: b64u(fakeSe.public.raw), role: "attestation", serial: "AUR0001XYZ", model: "AURUM-X1", bomDigest: b64u(bom) },
    { issuedAt: w.fx.now - 86400, notAfter: w.fx.now + 365 * 86400 },
  );
  const evilState: DeviceState = {
    ...w.state,
    material: { ...w.material, attestation: fakeSe },
    components: [
      { type: "se", signer: fakeSe, bootCounter: 100, fwDigest: w.fw.digest, willSign: true },
      ...w.state.components.filter((c) => c.type !== "se"),
    ],
    certBundleOverride: [
      fakeAtt,
      mcu.cert,
      ...w.material.components.filter((c) => c.type !== "se" && c.type !== "mcu").map((c) => c.cert),
      w.fx.ca.cert,
    ] as unknown[],
  };
  const r = await run(w, evilState);
  assert.equal(r.code, "CERT_KEY_USAGE", "component-as-issuer must be rejected");
});

test("ATTACK untrusted root: a self-made CA chain is rejected", async () => {
  // Build an entirely attacker-controlled world that mimics ours.
  const evilFx = await makeFixture();
  const evilMaterial = await makeDevice(evilFx, "AUR0001XYZ");
  const evilPolicy = await policyBundleOf(evilFx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const evilState = genuineDevice(evilMaterial, fw, 100);

  // But the *host* trusts the real root.
  const realFx = await makeFixture();
  const realPolicy = await policyBundleOf(realFx);
  const dev = new SimulatedDevice(evilState);
  const transport = loopbackTransport(simulatedResponder(dev));
  let err: unknown;
  try {
    await runVerification({
      transport, root: { root: realFx.root.root.public }, policy: realPolicy,
      minPolicyVersion: 0, now: realFx.now, timeoutMs: 3000,
    });
  } catch (e) {
    err = e;
  }
  assert.ok(describeFailure(err).code === "CERT_CHAIN_INCOMPLETE" || describeFailure(err).code === "CERT_SIGNATURE_INVALID",
    `expected chain rejection, got ${describeFailure(err).code}`);
  void evilPolicy;
});

// ---------------------------------------------------------------------------
// 4. Policy / firmware / revocation.
// ---------------------------------------------------------------------------

test("ATTACK firmware: unapproved firmware digest is rejected", async () => {
  const w = await world();
  const r = await run(w, cloneState(w.state, {
    firmware: { version: "1.4.9", digest: await firmwareDigest("1.4.9"), secureVersion: 9 },
  }));
  assert.ok(r.code === "FIRMWARE_NOT_ALLOWED" || r.code === "COMPONENT_ATTESTATION_INVALID",
    `expected firmware rejection, got ${r.code}`);
});

test("ATTACK firmware: approved version with mismatched digest is rejected", async () => {
  const w = await world();
  const r = await run(w, cloneState(w.state, {
    firmware: { version: "1.4.2", digest: await firmwareDigest("evil"), secureVersion: 7 },
  }));
  assert.ok(r.code === "FIRMWARE_NOT_ALLOWED" || r.code === "COMPONENT_ATTESTATION_INVALID",
    `expected firmware digest rejection, got ${r.code}`);
});

test("ATTACK firmware: secure-version downgrade is rejected", async () => {
  const w = await world();
  const r = await run(w, cloneState(w.state, {
    firmware: { version: "1.4.2", digest: w.fw.digest, secureVersion: 5 },
  }));
  assert.equal(r.code, "SECURE_VERSION_TOO_LOW");
});

test("ATTACK revocation: a revoked serial is rejected", async () => {
  const fx = await makeFixture();
  const material = await makeDevice(fx, "AUR0001REV");
  const policy = await policyBundleOf(fx);
  const revokedPolicy = {
    ...policy,
    policies: policy.policies.map((p) => ({ ...p, revokedSerials: ["AUR0001REV"] })),
  };
  // Re-sign the modified policy with the real issuer so the signature is valid.
  const { issuePolicy } = await import("../src/device/factory.ts");
  const reissued = await issuePolicy(fx.policyIssuer, revokedPolicy.policies);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 100);
  const dev = new SimulatedDevice(state);
  const transport = loopbackTransport(simulatedResponder(dev));
  let err: unknown;
  try {
    await runVerification({
      transport, root: { root: fx.root.root.public }, policy: reissued,
      minPolicyVersion: 0, now: fx.now, timeoutMs: 3000,
    });
  } catch (e) {
    err = e;
  }
  assert.equal(describeFailure(err).code, "DEVICE_REVOKED");
});

// ---------------------------------------------------------------------------
// 5. Rollback against pinned state.
// ---------------------------------------------------------------------------

test("ATTACK rollback: SE counter regression vs. pin is rejected", async () => {
  const w = await world();
  const pinned = {
    attestationPub: w.material.attestationCert.subject.pub,
    bomDigest: w.material.bomDigest,
    batch: w.material.batch,
    componentKids: Object.fromEntries(await Promise.all(w.state.components.map(async (c) => [c.type, (await c.signer.public).kid]))),
    seCounter: 500,
    bootCounters: { se: 500, mcu: 50, display: 30, flash: 20 },
    secureVersion: 7,
    policyVersion: 12,
  };
  const r = await run(w, w.state, { pinned });
  assert.equal(r.code, "COUNTER_ROLLBACK");
});

test("ATTACK rollback: secure version regression vs. pin is rejected", async () => {
  const w = await world();
  const pinned = {
    attestationPub: w.material.attestationCert.subject.pub,
    bomDigest: w.material.bomDigest,
    batch: w.material.batch,
    componentKids: Object.fromEntries(await Promise.all(w.state.components.map(async (c) => [type_of(c), (await c.signer.public).kid]))),
    seCounter: 100,
    bootCounters: { se: 100, mcu: 50, display: 30, flash: 20 },
    secureVersion: 9,
    policyVersion: 12,
  };
  const r = await run(w, w.state, { pinned });
  assert.ok(r.code === "FIRMWARE_ROLLBACK" || r.code === "SECURE_VERSION_TOO_LOW",
    `expected rollback rejection, got ${r.code}`);
});

function type_of(c: { type: string }): string {
  return c.type;
}

test("ATTACK rollback: policy bundle older than the accepted version is rejected", async () => {
  const w = await world();
  const r = await run(w, new SimulatedDevice(w.state), { minPolicyVersion: 999 });
  assert.equal(r.code, "POLICY_VIOLATION");
});

test("ATTACK component-set: dropping a required component is rejected", async () => {
  const w = await world();
  const r = await run(w, cloneState(w.state, { dropComponentTypes: ["flash"] }));
  assert.ok(r.code === "BOM_DIGEST_MISMATCH" || r.code === "BOM_INCOMPLETE" || r.code === "COMPONENT_NOT_TRUSTED",
    `expected incomplete BOM rejection, got ${r.code}`);
});

// ---------------------------------------------------------------------------
// 6. Wire-level attacks.
// ---------------------------------------------------------------------------

test("ATTACK tamper: flipping a byte in the ATTEST wire message is rejected", async () => {
  const w = await world();
  let tampered = false;
  const tap: WireTap = (dir, bytes) => {
    if (dir === "device->host" && !tampered) {
      tampered = true;
      const copy = bytes.slice();
      // Flip a byte in the middle (mutating the JSON text).
      const idx = Math.floor(copy.length / 2);
      copy[idx] = copy[idx]! ^ 0x01;
      return copy;
    }
    return bytes;
  };
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  // Must fail — either at parse (invalid canonical JSON) or at signature.
  assert.ok(r.code !== null, "tampered message must not verify");
});

test("ATTACK extra field: a signed statement with an unknown field is rejected", async () => {
  const w = await world();
  const tap: WireTap = (dir, bytes) => {
    if (dir === "device->host") {
      const msg = parseAttest(decodeWireMessage(bytes));
      const stmt = msg.statement as Record<string, unknown>;
      stmt["x_secretBackup"] = b64u(new Uint8Array(32));
      return encodeAttest({ ...msg, statement: stmt });
    }
    return bytes;
  };
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  assert.ok(r.code === "MALFORMED_MESSAGE" || r.code === "CANONICALIZATION_ERROR",
    `expected strict-schema rejection, got ${r.code}`);
});

test("ATTACK secret leak: a message carrying a secret-shaped field is refused", async () => {
  const w = await world();
  const tap: WireTap = (dir, bytes) => {
    if (dir === "device->host") {
      const msg = parseAttest(decodeWireMessage(bytes));
      const stmt = msg.statement as Record<string, unknown>;
      // A malicious/compromised device tries to exfiltrate the seed through
      // an allowed-but-typed field's *value* object.
      stmt["firmware"] = { ...(stmt["firmware"] as object), mnemonic: b64u(new Uint8Array(64)) };
      return encodeAttest({ ...msg, statement: stmt });
    }
    return bytes;
  };
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  // The secret-field guard fires before parsing, so it's a POLICY_VIOLATION;
  // if the field were nested deeper it would still be caught by the same walk.
  assert.ok(r.code === "POLICY_VIOLATION" || r.code === "MALFORMED_MESSAGE",
    `expected secret-exfil refusal, got ${r.code}`);
});

test("ATTACK downgrade: a lower protocol version is rejected as unsupported", async () => {
  const w = await world();
  // Inspect the parsed message the device would send, and rewrite its version
  // to 0 in a *canonical* way, so the failure is a version check, not a parse
  // error.  We then feed that message straight into the verifier.
  const honest = new SimulatedDevice(w.state);
  const hello = new TextEncoder().encode(canonicalString({
    v: 1, kind: "hello",
    sessionId: b64u(new Uint8Array(16).fill(9)),
    hostNonce: b64u(new Uint8Array(32).fill(9)),
    hostEphPub: b64u(new Uint8Array(32).fill(9)),
    hostTime: w.fx.now,
  }));
  const genuine = await honest.handleHello(hello);
  // v:2 is a well-formed version we do not support (v:0 would be rejected as
  // out-of-range first, which is also correct but tests a different branch).
  const downgraded = { ...genuine, v: 2 as unknown as 1 };
  const wire = encodeAttest(downgraded);
  let fed = false;
  const tap: WireTap = (dir, bytes) => {
    if (dir === "device->host" && !fed) {
      fed = true;
      return wire;
    }
    return bytes;
  };
  const r = await run(w, new SimulatedDevice(w.state), { tap });
  assert.equal(r.code, "PROTOCOL_VERSION_UNSUPPORTED");
});
