import test from "node:test";
import assert from "node:assert/strict";

import { makeDevice, makeFixture, policyBundleOf, firmwareDigest } from "../src/device/fixture.ts";
import { genuineDevice, SimulatedDevice } from "../src/device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../src/transport/loopback.ts";
import { runVerification, describeFailure } from "../src/manager/verify.ts";
import {
  deriveDisplayCode,
  makePresenceChallenge,
  presenceSigningBytes,
  verifyPresence,
  assertSasAcknowledged,
  type PresenceChallenge,
  type PresenceResponse,
} from "../src/manager/presence.ts";
import { b64u, randomBytes } from "../src/util/bytes.ts";
import { statementTranscriptHash } from "../src/attestation/statement.ts";

async function session() {
  const fx = await makeFixture();
  const material = await makeDevice(fx, "AUR0001XYZ");
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const state = genuineDevice(material, fw, 100);
  const transport = loopbackTransport(simulatedResponder(new SimulatedDevice(state)));
  const s = await runVerification({
    transport, root: { root: fx.root.root.public }, policy, minPolicyVersion: 0, now: fx.now,
  });
  return { fx, material, s };
}

/** Produce a signed presence response as the genuine SE would. */
async function signedResponse(
  material: Awaited<ReturnType<typeof makeDevice>>,
  challenge: PresenceChallenge,
  over: Partial<Omit<PresenceResponse, "sig">> = {},
): Promise<PresenceResponse> {
  const body = {
    v: 1 as const,
    kind: "presence-response" as const,
    presenceNonce: challenge.presenceNonce,
    pressed: true,
    displayCode: challenge.displayCode,
    ...over,
  };
  const sig = await material.attestation.sign(presenceSigningBytes(challenge, body));
  return { ...body, sig: b64u(sig) };
}

test("presence: a genuine button-press response verifies", async () => {
  const { material, s } = await session();
  const transcript = await statementTranscriptHash(s.device.statement);
  const nonce = randomBytes(24);
  const challenge = await makePresenceChallenge(s, transcript, nonce);
  const response = await signedResponse(material, challenge);
  await verifyPresence({
    challenge, response, device: s.device, expectedTranscriptHash: transcript,
  });
});

test("presence: no button press is rejected", async () => {
  const { material, s } = await session();
  const transcript = await statementTranscriptHash(s.device.statement);
  const challenge = await makePresenceChallenge(s, transcript, randomBytes(24));
  const response = await signedResponse(material, challenge, { pressed: false });
  let err: unknown;
  try {
    await verifyPresence({ challenge, response, device: s.device, expectedTranscriptHash: transcript });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "USER_PRESENCE_REQUIRED");
});

test("presence: a relayed response from another session's challenge fails", async () => {
  const { material, s } = await session();
  const transcript = await statementTranscriptHash(s.device.statement);
  // Challenge bound to a DIFFERENT transcript (as a relay would generate).
  const otherTranscript = new Uint8Array(32).fill(9);
  const challenge = await makePresenceChallenge(s, transcript, randomBytes(24));
  const wrongChallenge: PresenceChallenge = { ...challenge, transcriptHash: b64u(otherTranscript) };
  const response = await signedResponse(material, wrongChallenge);
  let err: unknown;
  try {
    await verifyPresence({ challenge, response, device: s.device, expectedTranscriptHash: transcript });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "USER_PRESENCE_INVALID");
});

test("presence: reusing an old presence nonce is rejected", async () => {
  const { material, s } = await session();
  const transcript = await statementTranscriptHash(s.device.statement);
  const challenge = await makePresenceChallenge(s, transcript, randomBytes(24));
  const oldResponse = await signedResponse(material, { ...challenge, presenceNonce: b64u(randomBytes(24)) });
  let err: unknown;
  try {
    await verifyPresence({ challenge, response: oldResponse, device: s.device, expectedTranscriptHash: transcript });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "USER_PRESENCE_INVALID");
});

test("presence: a forged signature is rejected", async () => {
  const { s } = await session();
  const transcript = await statementTranscriptHash(s.device.statement);
  const challenge = await makePresenceChallenge(s, transcript, randomBytes(24));
  const forged: PresenceResponse = {
    v: 1, kind: "presence-response", presenceNonce: challenge.presenceNonce,
    pressed: true, displayCode: challenge.displayCode, sig: b64u(new Uint8Array(64)),
  };
  let err: unknown;
  try {
    await verifyPresence({ challenge, response: forged, device: s.device, expectedTranscriptHash: transcript });
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "USER_PRESENCE_INVALID");
});

test("presence: display code is deterministic per nonce and 6 digits", async () => {
  const n = randomBytes(24);
  const a = await deriveDisplayCode(n);
  const b = await deriveDisplayCode(n);
  assert.equal(a, b);
  assert.match(a, /^\d{6}$/);
});

test("relay: a user-reported SAS mismatch is flagged as RELAY_SUSPECTED", async () => {
  const { s } = await session();
  let err: unknown;
  try {
    assertSasAcknowledged({ sasMatched: false, shownSas: s.sas }, s);
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "RELAY_SUSPECTED");
});

test("relay: a matching SAS acknowledgement passes", async () => {
  const { s } = await session();
  assert.doesNotThrow(() => assertSasAcknowledged({ sasMatched: true, shownSas: s.sas }, s));
});

test("relay: acknowledging a SAS that isn't the session's is flagged", async () => {
  const { s } = await session();
  let err: unknown;
  try {
    assertSasAcknowledged({ sasMatched: true, shownSas: "0000 0000 0000 0000 0000" }, s);
  } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "RELAY_SUSPECTED");
});
