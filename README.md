# wallet-device-attestation

Offline-capable **device authenticity & integrity verification** for a
hardware-crypto-wallet desktop companion app, written in TypeScript on Node's
built-in WebCrypto (no cryptography dependencies).

It answers one question, on first connection and on every later use:

> Is this the device we manufactured, running the firmware we approve, with the
> components we installed — **without seeing any wallet secret?**

…even though the attacker has held a genuine unit and can imitate every reaction
it produces, and even with no network.

---

## The problem this solves

A wallet bought from an unauthorised seller was opened and a chip replaced with
one that quietly exfiltrates the recovery phrase. The shell and box look
untouched. The user's funds are drained on first use.

You cannot detect this by:
- **looking at the device** (the case is identical);
- **fingerprinting its behaviour** (the attacker studied a genuine unit and can
  copy every response);
- **asking the device** (a compromised device lies).

The only thing an attacker *cannot* copy is **a private key they do not hold**.
Every defence here reduces to that, tied to a fresh challenge so recordings
cannot be replayed.

## How it works (three pillars)

1. **A factory-signed identity chain.** Each unit has a per-component Ed25519
   key. The factory signs a *BOM digest* — a hash over the exact set of component
   keys it installed — into the unit's attestation certificate. Only the factory
   root public key is preinstalled in the app; the chain is carried by the device
   and verified **offline**.

2. **A live, session-bound challenge.** Each component must sign a transcript
   derived from fresh 32-byte nonces and ephemeral X25519 keys. This proves the
   *actual hardware in front of you* holds its factory key — catching both a
   swapped chip **and** an impostor chip that copied a genuine unit's *public*
   key but not its private key.

3. **A pinned memory + human liveness check.** The app remembers each device's
   identity and highest tamper counters (sealed with AES-256-GCM) so a later
   session cannot roll back to older firmware or hide a swap. A short
   authentication string (compared on the device's own screen) and a physical
   button-press step defeat relays and man-in-the-middle.

Full design: [`docs/threat-model.md`](docs/threat-model.md) ·
[`docs/protocol.md`](docs/protocol.md).

## Quick start

Requires Node ≥ 23.6 (native TypeScript execution).

```bash
npm install            # dev deps only: typescript + @types/node
npm run typecheck      # strict tsc, no emit
npm test               # 85 tests (unit + end-to-end + attack + regression)
npm run demo           # narrative: genuine device, then the tampered one
npm run attacks        # every attack, with the exact rejection reason
```

### The demo, in one screen

```
SCENARIO 1 — A genuine device, first connection
  Genuine device — now remembered
  This is an authentic AURUM-X1 (serial AUR0001DEMO). We've saved its identity…
  Session code (compare with device screen): 5840 6984 7057 8504 7711

SCENARIO 3 — …a wallet bought on a third-party store, opened up, chip replaced…
  DO NOT USE THIS DEVICE
  One of the device's components is not certified. (COMPONENT_NOT_TRUSTED)
  → A component was swapped. Do not use the device for assets.
```

## Using it in the desktop app

```ts
import { DeviceManager } from "./src/manager/device-manager.ts";
import { renderVerdict } from "./src/manager/ui.ts";

const manager = new DeviceManager({
  root: { root: await importEd25519Public(rootPubRawBytes) }, // one key, shipped in-app
  policy,                       // signed firmware/revocation bundle, shipped in-app
  policyIssuerCerts: [policyCert, caCert],
  storage: { secret: await keychain.getOrCreate("attest-secret"), context: "profile-1" },
  now: () => Math.floor(Date.now() / 1000),
  persist: async (blob) => saveEncryptedState(blob),
  // Keep a monotonic high-water mark OUTSIDE the sealed file so an older copy
  // cannot be replayed to lower counters/policy (see docs/threat-model.md #17).
  epochGuard: {
    getHighWaterMark: () => keychain.getNumber("attest-epoch"),
    setHighWaterMark: (n) => keychain.setNumber("attest-epoch", n),
  },
  // Anti-relay gate: show the SAS to the user and resolve true only if the
  // device's own screen shows the same code.
  acknowledgeSas: async (sas) => ui.confirmSas(sas),
});

await manager.init(await loadEncryptedState());

// On connect and on every use:
const verdict = await manager.checkDevice(transport);
const shown = renderVerdict(verdict);
// Gate asset operations on verdict.kind === "genuine" || "authentic-but-unpinned".
// The UI must never downgrade a "rejected" verdict.

// For high-value operations, additionally require a physical press:
if (verdict.kind !== "rejected") {
  const presence = await manager.confirmPresence(verdict.session, pressOnDevice);
  if (!presence.ok) { /* block the operation */ }
}
```

`transport` is any `{ send(bytes), receive(): Promise<bytes> }` — a real
USB/WebUSB link, or the in-memory simulator used by tests and the demo. The
manager is transport-agnostic on purpose.

## Layout

```
src/
  util/        bytes, strict canonical-JSON parser, typed errors
  crypto/      WebCrypto primitives (Ed25519, X25519, HKDF, HMAC, AES-GCM)
  trust/       certificates & chain verification, policy bundles, sealed store
  protocol/    wire messages, session key schedule, key confirmation, SAS
  attestation/ statement model + the verifier (all checks, in order)
  manager/     DeviceManager (public API), presence, user-facing verdict text
  device/      factory provisioning + attack-configurable simulator
  transport/   in-memory loopback (direct or tapped, for tests)
  cli/         demo and attack-suite runner
tests/         unit, end-to-end, attack suite, and review regressions
docs/          threat model and protocol spec
```

## What the test suite proves

`tests/e2e-attacks.test.ts` builds an adversary that **speaks the protocol
correctly** and varies one capability at a time, then asserts the *specific*
failure code. 24 attack tests, including:

- swapped component; impostor chip with a copied public key; certificate swap;
- replayed attestation; stale nonce; mixed identities; forged statement;
  attacker-made CA;
- unapproved/mismatched firmware; secure-version downgrade; missing component;
- counter rollback; policy downgrade; revoked serial;
- wire tampering; unknown-field smuggling; secret-shaped field injection;
- protocol downgrade.

Plus `tests/e2e-manager.test.ts` for the actual product flows (first-connect
pinning, every-use re-check, restart persistence, rollback across restarts,
presence), and `tests/unit-store.test.ts` for at-rest sealing and tamper
detection.

## Adversarial review, and what it found

This code was put through an independent adversarial review that wrote working
exploits. It found real bugs, which are now fixed and locked down by
`tests/regression-review.test.ts`:

1. **Any certified component key could act as a CA** — one extracted chip key
   forged a whole "genuine" device with a swap-in Secure Element. Fixed by
   enforcing the two-level role hierarchy in `verifyChain` (`CERT_KEY_USAGE`).
2. **Policy-bundle downgrade was a no-op** — the "minimum accepted version" was
   computed from the very bundle being checked. Fixed by persisting a global
   policy high-water mark (survives store deletion via the `EpochGuard`).
3. Per-device policy-version rollback was not compared to the pin — now enforced.
4. **Store replay/deletion** could lower counters or reset memory — now closed by
   an external `EpochGuard` high-water mark (epoch + policy floor).
5. The relay/SAS defense was documented but not wired into the main flow — now
   `checkDevice` enforces `acknowledgeSas` before returning `genuine`.
6. Pin lookup used an unverified serial hint — now the resolver receives the
   certificate-bound, verified serial.

## Honest limitations

See [`docs/threat-model.md`](docs/threat-model.md) §"What we explicitly do not
claim". The big one: **a chip that copies both the public *and* private key is
indistinguishable from the original** — because that key *is* the component's
identity. That requires a physically-unclonable function to narrow, noted as
future work. We do not claim protection against a fully compromised host OS or
a leaked factory root key.

## Non-goals

This library does not implement USB transport, the OS-keychain binding, code
signing, or firmware update delivery. It implements the verification logic those
pieces feed into.
