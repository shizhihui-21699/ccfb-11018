/**
 * Device simulator: the *device* side of the handshake, as a genuine unit and
 * as the range of attacks we care about.
 *
 * Why a configurable simulator rather than only unit tests
 * --------------------------------------------------------
 * The threat model says the attacker has a real device and can "study and
 * imitate its reactions."  The only honest validation is an adversary that
 * speaks the protocol perfectly and varies exactly one capability at a time
 * (does it hold the right private key? can it answer the live challenge? did
 * it swap a component? is it replaying a recording?).  Each `DeviceState`
 * override encodes one such capability, so the integration tests assert the
 * *specific* failure code a real attack would produce — not a parse error.
 *
 * Every variant produces wire-canonical messages.  If a variant cannot finish
 * the handshake, that is a protocol win, not a malformed message.
 */

import {
  generateX25519,
  type Ed25519Signer,
} from "../crypto/primitives.ts";
import { b64u, b64uDecode, type Bytes } from "../util/bytes.ts";
import { canonicalString } from "../util/canonical.ts";
import type { DeviceMaterial } from "./factory.ts";
import {
  decodeWireMessage,
  parseHello,
  parseConfirm,
  encodeReady,
  type AttestMessage,
  type ConfirmMessage,
  type HelloMessage,
  type ReadyMessage,
} from "../protocol/messages.ts";
import {
  statementSigningBytes,
  statementTranscriptHash,
  type AttestationStatement,
  type ComponentClaim,
} from "../attestation/statement.ts";
import {
  checkConfirmation,
  establishSession,
  makeConfirmation,
  type SessionKeys,
} from "../protocol/session.ts";
import type { ComponentType } from "../trust/certs.ts";
import { randomBytes } from "../util/bytes.ts";

export interface SimComponent {
  readonly type: ComponentType;
  readonly signer: Ed25519Signer;
  readonly bootCounter: number;
  readonly fwDigest: string;
  /**
   * The public key this component *reports* in its statement.  Defaults to its
   * own key.  An attacker who cloned a genuine chip's public key can set this
   * to the genuine key while signing with a different (or no) private key —
   * the "impostor that copied the public key" attack.  Only the live challenge
   * (which requires the matching private key) catches this.
   */
  readonly claimedPub?: string;
  /**
   * Whether this component will actually sign the live challenge.
   * `false` models a swapped chip that lacks the factory private key: it emits
   * a syntactically valid but invalid signature.
   */
  readonly willSign: boolean;
}

export interface DeviceState {
  readonly material: DeviceMaterial;
  readonly firmware: { version: string; digest: string; secureVersion: number };
  readonly seCounter: number;
  readonly batch: string;
  readonly components: ReadonlyArray<SimComponent>;
  /** Statement claims a different serial than its certificate (identity swap). */
  readonly statementSerialOverride?: string;
  /** Present a different device's certificate bundle (clone / mix-and-match). */
  readonly certBundleOverride?: ReadonlyArray<unknown>;
  /** Sign the statement with a non-SE key (forged attestation). */
  readonly statementSignerOverride?: Ed25519Signer;
  /** Echo a stale hostNonce instead of the live one (replay of a recording). */
  readonly hostNonceOverride?: string;
  /** Reuse a fixed ephemeral key pair (weak RNG / replay). */
  readonly fixedEph?: { readonly privateKey: CryptoKey; readonly publicRaw: Bytes };
  /** Report a statement that reuses a subset of certs but lies about BOM. */
  readonly dropComponentTypes?: ReadonlyArray<ComponentType>;
}

export function genuineDevice(
  material: DeviceMaterial,
  firmware: { version: string; digest: string; secureVersion: number },
  seCounter: number,
  bootCounters: Readonly<Record<string, number>> = {},
): DeviceState {
  return {
    material,
    firmware,
    seCounter,
    batch: material.batch,
    components: material.components.map((c) => ({
      type: c.type,
      signer: c.signer,
      bootCounter: bootCounters[c.type] ?? 1,
      fwDigest: firmware.digest,
      willSign: true,
    })),
  };
}

interface DeviceSession {
  readonly keys: SessionKeys;
  readonly statement: AttestationStatement;
  readonly deviceEphPub: Bytes;
}

/**
 * One simulated device.  Holds at most one in-flight handshake; a second HELLO
 * replaces it (as a real device would restart the exchange).
 */
export class SimulatedDevice {
  private pending: DeviceSession | null = null;
  readonly state: DeviceState;

  constructor(state: DeviceState) {
    this.state = state;
  }

  /** HELLO -> ATTEST.  Throws only on genuinely malformed input. */
  async handleHello(helloWire: Bytes): Promise<AttestMessage> {
    const hello = parseHello(decodeWireMessage(helloWire));
    const deviceEph = this.state.fixedEph ?? (await generateX25519());
    const deviceEphPub = deviceEph.publicRaw;

    const deviceNonce = randomBytes(32);
    const hostNonce = this.state.hostNonceOverride ?? hello.hostNonce;

    const active = this.state.dropComponentTypes
      ? this.state.components.filter((c) => !this.state.dropComponentTypes!.includes(c.type))
      : this.state.components;

    // Skeleton first, so components can sign the transcript derived from it.
    const skeleton: AttestationStatement = {
      v: 1,
      kind: "statement",
      serial: this.state.statementSerialOverride ?? this.state.material.serial,
      model: this.state.material.model,
      attestationPub: b64u(this.state.material.attestation.public.raw),
      sessionId: hello.sessionId,
      hostNonce,
      deviceNonce: b64u(deviceNonce),
      hostEphPub: hello.hostEphPub,
      deviceEphPub: b64u(deviceEphPub),
      firmware: this.state.firmware,
      seCounter: this.state.seCounter,
      batch: this.state.batch,
      components: active.map(
        (c): ComponentClaim => ({
          type: c.type,
          pub: c.claimedPub ?? b64u(c.signer.public.raw),
          challengeSig: "",
          bootCounter: c.bootCounter,
          fwDigest: c.fwDigest,
        }),
      ),
    };
    const transcript = await statementTranscriptHash(skeleton);

    const signedComponents: ComponentClaim[] = [];
    for (let i = 0; i < active.length; i++) {
      const comp = active[i]!;
      const base = skeleton.components[i]!;
      if (!comp.willSign) {
        signedComponents.push({ ...base, challengeSig: b64u(new Uint8Array(64)) });
        continue;
      }
      const sig = await comp.signer.sign(transcript);
      signedComponents.push({ ...base, challengeSig: b64u(sig) });
    }
    const statement: AttestationStatement = { ...skeleton, components: signedComponents };

    const signer = this.state.statementSignerOverride ?? this.state.material.attestation;
    const statementSig = await signer.sign(statementSigningBytes(statement));

    // Derive session keys exactly as the host will, so we can confirm.
    const keys = await establishSession({
      myPrivateKey: deviceEph.privateKey,
      myEphPub: deviceEphPub,
      peerEphPub: b64uDecode(hello.hostEphPub),
      isHost: false,
    });

    this.pending = { keys, statement, deviceEphPub };

    const bundle = this.state.certBundleOverride ?? this.state.material.certBundle;
    return {
      v: 1,
      kind: "attest",
      sessionId: hello.sessionId,
      hostNonce,
      deviceNonce: statement.deviceNonce,
      deviceEphPub: statement.deviceEphPub,
      certBundle: bundle as ReadonlyArray<unknown>,
      statement: JSON.parse(canonicalString(statement)) as unknown,
      statementSig: b64u(statementSig),
    };
  }

  /** CONFIRM -> READY.  Verifies the host's key confirmation first. */
  async handleConfirm(confirmWire: Bytes): Promise<ReadyMessage> {
    const confirm = parseConfirm(decodeWireMessage(confirmWire));
    if (!this.pending) {
      // A device that never sent ATTEST cannot confirm; treat as protocol error.
      throw new Error("sim: confirm before hello");
    }
    const { keys, statement } = this.pending;
    const transcript = await statementTranscriptHash(statement);
    const hostOk = await checkConfirmation(keys, "host", transcript, b64uDecode(confirm.hostConfirm));
    if (!hostOk) {
      // The host did not prove knowledge of the shared secret; refuse to send
      // our own confirmation (so a bad host cannot harvest it).
      throw new Error("sim: host key confirmation failed");
    }
    const deviceConfirm = await makeConfirmation(keys, "device", transcript);
    return {
      v: 1,
      kind: "ready",
      sessionId: confirm.sessionId,
      transcriptHash: b64u(transcript),
      deviceConfirm: b64u(deviceConfirm),
    };
  }

  /** The SAS this device would display on its own screen (for relay tests). */
  deviceSas(): string | null {
    return this.pending ? this.pending.keys.sas : null;
  }
}

export { encodeReady, type ConfirmMessage, type HelloMessage };
