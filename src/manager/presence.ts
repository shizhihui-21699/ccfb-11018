/**
 * User presence & liveness — the part a remote relay cannot fake.
 *
 * Every prior check can, in principle, be satisfied by a device that is
 * genuinely present on the wire.  The remaining attack is *relay*: a malicious
 * USB dongle or a compromised host forwards bytes between the desktop app and
 * a real genuine device somewhere else (e.g., the attacker's own, or a victim's
 * still-connected wallet), and the app talks to a "genuine" device that is not
 * the one in the user's hand.
 *
 * We close this with two independent, cheap mechanisms:
 *
 *  1. **SAS comparison** (already in the session).  The host shows a 20-digit
 *     code derived from the ECDH secret; the device shows the same code on its
 *     OWN trusted display.  A transparent relay cannot make both sides show the
 *     same code unless it relays faithfully — in which case the code matches
 *     and the user *is* talking to the device they are holding.  A relay that
 *     re-keys gets two different codes.  The device's display is driven by the
 *     SE over an internal, non-exportable path; a swapped display chip is
 *     caught by the per-component challenge in the attestation.
 *
 *  2. **Physical confirmation** (this module).  For operations the policy marks
 *     as high-value, the host sends a presence challenge bound to the session
 *     transcript and a random `presenceNonce`.  The device must (a) display a
 *     short code derived from it and (b) require a physical button press before
 *     the SE signs the challenge.  An unattended relay has no human to press
 *     the button, and the presence signature is bound to THIS session's
 *     transcript, so it cannot be replayed from an earlier press.
 *
 * Secret-free: the presence challenge contains only public binding data (a
 * hash and a random nonce).  Pressing the button authorizes *presence*, not any
 * particular transaction; it reveals nothing about the wallet.
 */

import {
  ed25519Verify,
  hmacSign,
  importEd25519Public,
} from "../crypto/primitives.ts";
import { b64u, b64uDecode, concat, utf8Encode, type Bytes } from "../util/bytes.ts";
import { fail } from "../util/errors.ts";
import { canonicalString } from "../util/canonical.ts";
import { digestOf } from "../crypto/primitives.ts";
import type { TrustedDevice } from "../attestation/verifier.ts";
import type { Session } from "./verify.ts";

export interface PresenceChallenge {
  readonly v: 1;
  readonly kind: "presence";
  readonly sessionId: string;
  readonly transcriptHash: string;
  readonly presenceNonce: string;
  /** Human-visible short code the device must render. */
  readonly displayCode: string;
}

export interface PresenceResponse {
  readonly v: 1;
  readonly kind: "presence-response";
  readonly presenceNonce: string;
  /** True iff a physical button was pressed during the challenge window. */
  readonly pressed: boolean;
  /** Device renders the same 6-digit code it shows on its screen. */
  readonly displayCode: string;
  /** SE signature over the challenge+response, binding presence to session. */
  readonly sig: string;
}

/** Build a presence challenge bound to the session transcript. */
export async function makePresenceChallenge(
  session: Session,
  transcriptHash: Bytes,
  presenceNonce: Bytes,
): Promise<PresenceChallenge> {
  const challenge: PresenceChallenge = {
    v: 1,
    kind: "presence",
    sessionId: session.device.statement.sessionId,
    transcriptHash: b64u(transcriptHash),
    presenceNonce: b64u(presenceNonce),
    displayCode: await deriveDisplayCode(presenceNonce),
  };
  return challenge;
}

export function presenceSigningBytes(c: PresenceChallenge, r: Omit<PresenceResponse, "sig">): Bytes {
  return concat(
    utf8Encode("presence/v1\u0000"),
    utf8Encode(canonicalString({
      challenge: {
        v: c.v, kind: c.kind, sessionId: c.sessionId,
        transcriptHash: c.transcriptHash, presenceNonce: c.presenceNonce, displayCode: c.displayCode,
      },
      response: {
        v: r.v, kind: r.kind, presenceNonce: r.presenceNonce,
        pressed: r.pressed, displayCode: r.displayCode,
      },
    })),
  );
}

/**
 * Verify a presence response against the challenge and the session.
 *
 * Requirements:
 *  - `pressed === true`,
 *  - the device's displayed code equals the one the challenge derived,
 *  - the nonce matches exactly (no reuse of an older press),
 *  - the SE signature verifies under the *pinned* attestation key.
 *
 * The display-code equality is what defeats a relay: an attacker who forwards
 * bytes to a remote genuine device will see that device show ITS code, which is
 * derived from the same nonce and will therefore match — but the remote device
 * will not have anyone press the button, and if the attacker somehow presses it
 * remotely we additionally require the host-side SAS to match (see
 * `assertSasMatches`).  Together these force a human physically present at the
 * device in the user's hand.
 */
export async function verifyPresence(input: {
  challenge: PresenceChallenge;
  response: PresenceResponse;
  device: TrustedDevice;
  expectedTranscriptHash: Bytes;
}): Promise<void> {
  const { challenge, response, device } = input;

  if (challenge.transcriptHash !== b64u(input.expectedTranscriptHash)) {
    fail("USER_PRESENCE_INVALID", "presence challenge is bound to a different session transcript");
  }
  if (response.presenceNonce !== challenge.presenceNonce) {
    fail("USER_PRESENCE_INVALID", "presence response nonce mismatch (stale press?)");
  }
  if (!response.pressed) {
    fail("USER_PRESENCE_REQUIRED", "no physical button press recorded");
  }
  const expectedCode = await deriveDisplayCode(b64uDecode(challenge.presenceNonce));
  if (response.displayCode !== expectedCode || response.displayCode !== challenge.displayCode) {
    fail("USER_PRESENCE_INVALID", "device display code does not match the challenge (possible relay)");
  }
  const body: Omit<PresenceResponse, "sig"> = {
    v: response.v,
    kind: response.kind,
    presenceNonce: response.presenceNonce,
    pressed: response.pressed,
    displayCode: response.displayCode,
  };
  const sePub = await importEd25519Public(b64uDecode(device.attestationPub));
  if (!(await ed25519Verify(sePub, presenceSigningBytes(challenge, body), b64uDecode(response.sig)))) {
    fail("USER_PRESENCE_INVALID", "presence response signature is invalid");
  }
}

/** 6-digit decimal code from the presence nonce — what the user compares. */
export async function deriveDisplayCode(presenceNonce: Bytes): Promise<string> {
  const d = await digestOf("presence-display/v1", { nonce: b64u(presenceNonce) });
  // 6 digits from 3 bytes, modulo 10^6.
  const v = ((d[0]! << 16) | (d[1]! << 8) | d[2]!) % 1_000_000;
  return v.toString().padStart(6, "0");
}

/**
 * The host-side half of the anti-relay check: the SAS the host derived must be
 * confirmed by the user against the device's own screen.  This function only
 * enforces *that the app showed it and the user acknowledged a match* — the
 * actual comparison is a human act, by design.  A relay that re-keys produces
 * two different SAS values and the human sees the mismatch.
 */
export function assertSasAcknowledged(ack: { sasMatched: boolean; shownSas: string }, session: Session): void {
  if (!ack.sasMatched) {
    fail("RELAY_SUSPECTED", "user reported the on-device code does not match (possible relay / MITM)");
  }
  if (ack.shownSas !== session.sas) {
    fail("RELAY_SUSPECTED", "acknowledged SAS does not match the session SAS");
  }
}

/** Compute the device-side SAS input the same way the host does (for the
 *  simulator's display).  Kept here so both sides share one definition. */
export async function deviceSasFromKeys(sessionKeys: { sas: string }): Promise<string> {
  return sessionKeys.sas;
}

export { hmacSign };
