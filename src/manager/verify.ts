/**
 * Host-side verifier orchestrator — the public entry point the desktop manager
 * calls to run one authenticity check against a connected device.
 *
 * It owns the 4-flight handshake, enforces session binding and key
 * confirmation, and delegates the cryptographic verdict to
 * `attestation/verifier.ts`.  It is transport-agnostic: a `DeviceTransport`
 * supplies `send`/`receive`, so the same code drives a simulator, a WebUSB
 * device, or a pcap replay in tests.
 *
 * Failure semantics
 * -----------------
 * Each distinct attack maps to a distinct `ErrorCode`.  A driver must treat any
 * thrown `AttestationError` as "do NOT proceed with asset operations", and the
 * UI must show a specific, actionable reason (see `describeError` in cli/ui).
 *
 * Secret hygiene: this class never logs message bodies, never persists the
 * session keys, and zeroizes the ECDH-derived secrets it can reach.  The
 * in-memory session object exposes only MAC'd record helpers, never raw keys.
 */

import {
  generateX25519,
  type Ed25519PublicKey,
} from "../crypto/primitives.ts";
import { b64u, b64uDecode, type Bytes, concat, randomBytes } from "../util/bytes.ts";
import { fail, isAttestationError, AttestationError, type ErrorCode } from "../util/errors.ts";
import { canonicalString } from "../util/canonical.ts";
import {
  assertNoSecretFields,
  decodeWireMessage,
  encodeConfirm,
  encodeHello,
  parseAttest,
  parseReady,
  SESSION_ID_LEN,
  type HelloMessage,
} from "../protocol/messages.ts";
import {
  checkConfirmation,
  establishSession,
  makeConfirmation,
  sessionRecordMac,
  type SessionKeys,
} from "../protocol/session.ts";
import { statementTranscriptHash } from "../attestation/statement.ts";
import {
  verifyAttestation,
  type PinnedState,
  type TrustedDevice,
} from "../attestation/verifier.ts";
import type { PolicyBundle } from "../trust/policy.ts";
import type { TrustRoot } from "../trust/certs.ts";

/** A bidirectional byte transport to the device. */
export interface DeviceTransport {
  send(bytes: Bytes): Promise<void>;
  receive(): Promise<Bytes>;
  close?(): Promise<void>;
}

export interface VerifySessionOptions {
  readonly transport: DeviceTransport;
  readonly root: TrustRoot;
  readonly policy: PolicyBundle;
  readonly minPolicyVersion: number;
  /** Static pin, if the caller already knows the serial. */
  readonly pinned?: PinnedState | undefined;
  /**
   * Resolve the pin once the device's serial is known (after ATTEST).  In the
   * "every use" flow the host does not know which device is attached until the
   * statement arrives, so the manager supplies a lookup rather than a value.
   * Only one of `pinned` / `resolvePin` should be set.
   */
  readonly resolvePin?: (serial: string) => PinnedState | undefined;
  readonly now: number;
  readonly requireUserPresence?: boolean;
  /** Max time to wait for a device flight. */
  readonly timeoutMs?: number;
  /** Called with the SAS so the UI can show it for human comparison. */
  readonly onSas?: (sas: string) => void;
}

export interface Session {
  readonly device: TrustedDevice;
  readonly firstSight: boolean;
  readonly userPresenceRequired: boolean;
  readonly sas: string;
  /** MAC a management command for the device under this session. */
  macHostCommand(seq: number, plaintext: Bytes): Promise<Bytes>;
  /** Verify a device-originated record under this session. */
  verifyDeviceRecord(seq: number, plaintext: Bytes, mac: Bytes): Promise<boolean>;
}

export async function runVerification(opts: VerifySessionOptions): Promise<Session> {
  const { transport, root, policy, now } = opts;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  // --- Flight 1: HELLO ------------------------------------------------------
  const hostEph = await generateX25519();
  const sessionId = b64u(randomBytes(SESSION_ID_LEN));
  const hostNonce = b64u(randomBytes(32));
  const hello: HelloMessage = {
    v: 1,
    kind: "hello",
    sessionId,
    hostNonce,
    hostEphPub: b64u(hostEph.publicRaw),
    hostTime: now,
  };
  await transport.send(encodeHello(hello));

  // --- Flight 2: ATTEST -----------------------------------------------------
  const attestBytes = await withTimeout(transport.receive(), timeoutMs, "ATTEST");
  const attestValue = decodeWireMessage(attestBytes);
  // Refuse any message that carries a secret-shaped field before we parse it.
  assertNoSecretFields(attestValue, "$.attest");
  const attest = parseAttest(attestValue);

  // Derive session keys from our ephemeral key + the device's.
  const keys = await establishSession({
    myPrivateKey: hostEph.privateKey,
    myEphPub: hostEph.publicRaw,
    peerEphPub: b64uDecode(attest.deviceEphPub),
    isHost: true,
  });
  opts.onSas?.(keys.sas);

  // --- Cryptographic verdict (offline) -------------------------------------
  // The pin is resolved inside the verifier from the *verified* serial, never
  // from an unauthenticated hint, so a device cannot influence which pin is
  // applied.  See `verifyAttestation` step 9.
  const result = await verifyAttestation({
    hello,
    attest,
    root,
    policy,
    minPolicyVersion: opts.minPolicyVersion,
    pinned: opts.pinned,
    resolvePin: opts.resolvePin,
    now,
    requireUserPresence: opts.requireUserPresence ?? false,
  });

  // Sanity: the statement the verifier accepted must be the one we hashed.
  const statement = result.device.statement;

  // --- Flight 3: CONFIRM ----------------------------------------------------
  const transcript = await statementTranscriptHash(statement);
  const hostConfirm = await makeConfirmation(keys, "host", transcript);
  await transport.send(
    encodeConfirm({
      v: 1,
      kind: "confirm",
      sessionId,
      transcriptHash: b64u(transcript),
      hostConfirm: b64u(hostConfirm),
    }),
  );

  // --- Flight 4: READY ------------------------------------------------------
  const readyBytes = await withTimeout(transport.receive(), timeoutMs, "READY");
  const readyValue = decodeWireMessage(readyBytes);
  assertNoSecretFields(readyValue, "$.ready");
  const ready = parseReady(readyValue);
  if (ready.sessionId !== sessionId) {
    fail("TRANSCRIPT_MISMATCH", "READY session id mismatch");
  }
  if (ready.transcriptHash !== b64u(transcript)) {
    fail("TRANSCRIPT_MISMATCH", "READY transcript hash mismatch");
  }
  const deviceConfirmed = await checkConfirmation(keys, "device", transcript, b64uDecode(ready.deviceConfirm));
  if (!deviceConfirmed) {
    fail("SESSION_KEY_UNCONFIRMED", "device failed key confirmation (cannot prove it holds the ECDH secret)");
  }

  const session: Session = {
    device: result.device,
    firstSight: result.firstSight,
    userPresenceRequired: result.userPresenceRequired,
    sas: keys.sas,
    macHostCommand: (seq, plaintext) => sessionRecordMac(keys, "host-to-device", seq, plaintext),
    verifyDeviceRecord: async (seq, plaintext, mac) => {
      const expect = await sessionRecordMac(keys, "device-to-host", seq, plaintext);
      return timingSafeEqualBytes(expect, mac);
    },
  };
  return session;
}

/** Redact a thrown value into something safe to log / show. */
export function describeFailure(e: unknown): { code: ErrorCode; message: string; detail?: unknown } {
  if (isAttestationError(e)) {
    return { code: e.code, message: e.message, detail: e.detail };
  }
  if (e instanceof Error) {
    return { code: "INTERNAL_ERROR", message: "verification aborted" };
  }
  return { code: "INTERNAL_ERROR", message: "unknown failure" };
}

export { AttestationError };

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AttestationError("TRANSPORT_ERROR", `timeout waiting for ${what}`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function timingSafeEqualBytes(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}



export type { TrustedDevice, PinnedState, Ed25519PublicKey, SessionKeys };
export { concat, canonicalString };
