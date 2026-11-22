# Threat model

This document states exactly what the device-authenticity feature protects
against, what it does **not** protect against, and why. It is written so a
security reviewer can agree or disagree with each line, rather than take a
"secure" claim on faith.

## What we are defending

A user buys a wallet from an unauthorised third-party seller. The device has
been physically opened and a component (or the Secure Element's firmware) has
been replaced with a version that exfiltrates the recovery phrase. The case and
packaging look untouched. We must let the desktop companion app decide, **on
first connection and on every subsequent use, offline**, whether:

1. the device is one we manufactured (genuine), and
2. its firmware and key components are the ones we installed and approve.

…**without the verification itself ever exposing wallet secrets.**

## Adversary capabilities we assume

The adversary:

- **has held a genuine device** and can study it, including its wire protocol,
  timing, and every response it produces;
- **can read this source code** and the full protocol (Kerckhoffs's principle);
- **can impersonate any device** on the USB/serial wire, replay recordings, and
  answer in any way a piece of software can (we never rely on "behaviour");
- **controls the third-party distribution channel** for the hardware;
- **may have extracted public keys** from a genuine unit (public keys are not
  secret);
- **cannot factor / forge** Ed25519 signatures, invert SHA-256, or break X25519,
  under standard hardness assumptions.

## Trust anchors (what is assumed honest)

- The **factory root private key** is never present on any device or in the app;
  only its public key is shipped inside the desktop app. If it leaks, the whole
  scheme fails — this is the one irreducible trust assumption.
- The **desktop app binary** and the **OS keychain** used to seal the trust store
  are assumed uncompromised. A host that is fully owned by the attacker can lie
  to its own user; no in-app check can prevent that (see "Out of scope").
- The **clock** is roughly correct (bounded ±5 min skew is tolerated for cert and
  policy validity). A wildly wrong clock can cause false *rejections*, never a
  false acceptance.

## Attacks in scope, and the specific defence

| # | Attack | Defence (where) | Failure code |
|---|--------|-----------------|--------------|
| 1 | Swap a component for one without the factory key | per-component live challenge over a fresh transcript (`attestation/verifier.ts` step 7) | `COMPONENT_ATTESTATION_INVALID` |
| 2 | Swap a component but **copy its public key** (impostor chip) | same live challenge — the impostor cannot sign with the private key it lacks | `COMPONENT_ATTESTATION_INVALID` |
| 3 | Swap a component **and** its certificate | BOM digest (CA-signed `bomDigest`) no longer matches the presented set | `BOM_DIGEST_MISMATCH` |
| 4 | Ship a wholly counterfeit device with a self-made CA | certificate chain must terminate at the **pinned root** | `CERT_CHAIN_INCOMPLETE` / `CERT_SIGNATURE_INVALID` |
| 5 | Replay a recorded genuine handshake | 32-byte per-connection `hostNonce` + fresh device nonce + ephemeral ECDH, all inside the signed transcript | `CHALLENGE_MISMATCH` / `TRANSCRIPT_MISMATCH` |
| 6 | Present another genuine device's certificates with a different serial | cert serial/model are signed and compared to the statement | `DEVICE_MISMATCH` |
| 7 | Run modified / unofficial firmware | firmware version+digest must be in the signed, approved policy list | `FIRMWARE_NOT_ALLOWED` |
| 8 | Downgrade to older firmware after a recall | secure-version monotonicity vs. the pin **and** the policy | `FIRMWARE_ROLLBACK` / `SECURE_VERSION_TOO_LOW` |
| 9 | Roll back tamper counters to hide a swap | counters pinned and required monotonic across connections | `COUNTER_ROLLBACK` |
| 10 | Use a device the factory has recalled | signed revocation list in the policy bundle | `DEVICE_REVOKED` / `KEY_REVOKED` |
| 11 | Serve a stale policy bundle to re-admit an old device | global `minPolicyVersion` high-water mark persisted in the store **and** per-device pin; `init` refuses a bundle older than one already accepted | `POLICY_VIOLATION` |
| 12 | Smuggle extra signed fields past the verifier | strict schema (`onlyKeys`) + canonical-JSON byte round-trip | `MALFORMED_MESSAGE` / `CANONICALIZATION_ERROR` |
| 13 | Force the app to accept a message carrying wallet secrets | `assertNoSecretFields` walks every inbound message before parsing | `POLICY_VIOLATION` |
| 14 | An active relay / MITM between app and device | SAS code comparison + per-component display. **Must be wired:** `DeviceManager` requires the configured `acknowledgeSas` callback to report a match before returning `genuine`; a re-keying relay also fails the `hostEphPub` binding outright | `RELAY_SUSPECTED` / `TRANSCRIPT_MISMATCH` |
| 15 | Unattended remote relay of a real device | physical button-press presence challenge bound to the session transcript (`confirmPresence`) | `USER_PRESENCE_REQUIRED` |
| 16 | Tamper with the on-disk pin database | AES-256-GCM seal with AAD-bound epoch; tamper ⇒ auth failure, not reset | `TRUST_STORE_SEAL_INVALID` / `TRUST_STORE_CORRUPT` |
| 17 | Replay an *older, valid* sealed store to lower counters/policy, or delete it to reset memory | external `EpochGuard` high-water mark (epoch **and** policy floor) kept outside the blob (keychain/TPM); `load` rejects a lower epoch, and a deleted file still inherits the policy floor. **Requires the host to supply a guard**; without one, this is the host's responsibility | `TRUST_STORE_REPLAY` / `POLICY_VIOLATION` |
| 18 | Use a certified component key as a CA to forge an attestation cert | chain verifier enforces the two-level hierarchy: only a `device-ca` may issue, and only the root may sign a `device-ca` | `CERT_KEY_USAGE` |

## What we explicitly do **not** claim

These are honest limitations, each with the reason and the mitigation status.

1. **A chip that copies both the public *and* private key.** If an attacker
   extracted a component's private key from a genuine unit and built a chip that
   signs correctly with it, it is cryptographically indistinguishable from the
   original chip. This is *by design* — the key **is** the component's identity.
   Mitigation: such a device is functionally the genuine component; we cannot
   tell it apart, and neither can any challenge-response scheme that does not
   use physically-unclonable functions. Hardware PUFs would narrow this; see
   "Future work".

2. **A fully compromised host OS.** If the user's computer is owned by malware,
   it can show a fake "genuine" screen. The checks still run, but their output
   can be lied about. Out of scope; the SAS is shown on the *device's* own
   display precisely so the human has one trusted channel the host cannot fake.

3. **A leak of the factory root private key.** Catastrophic and out of scope
   beyond key custody. Mitigation: root is offline (HSM), CA keys are
   intermediate and revocable via policy.

4. **Side channels in the device's own firmware.** We verify identity, firmware
   measurements, and component presence — not whether approved firmware is
   *free* of exploitable bugs. That is a firmware-assurance problem, not an
   authenticity problem.

5. **Supply-chain tampering of the desktop app.** If the app itself is trojaned,
   nothing in it can be trusted. Mitigation: code signing, OS-level update
   security (out of scope here).

6. **Denial of service.** An attacker can always make the device fail to
   respond. We treat that as `rejected`/`TRANSPORT_ERROR`, never as "authentic".

7. **Store replay without a host-provided `EpochGuard`.** Sealing stops
   *tampering* with the store file, but an intact older blob can only be
   rejected if the host keeps a monotonic high-water mark somewhere the attacker
   cannot roll back (keychain, TPM). `DeviceManager` supports this via
   `EpochGuard`; if the host omits it, replay protection is the host's
   responsibility and is not claimed here.

8. **Relay detection is opt-in via `acknowledgeSas`.** The cryptographic
   handshake detects a *re-keying* relay by itself (`TRANSCRIPT_MISMATCH`), but a
   *transparent* relay to a genuine remote device only differs in the SAS shown
   on the two screens. `checkDevice` enforces the relay gate only when the host
   supplies `acknowledgeSas`; the UI must implement it (and the physical
   `confirmPresence` for high-value operations) for the relay defense to be
   active end-to-end.

## Why verification cannot leak secrets

This is a structural property, not a promise:

- The protocol messages are typed by closed schemas. There is no field that can
  carry a seed, xprv, mnemonic, PIN, or passphrase. `assertNoSecretFields`
  additionally rejects any inbound object with a secret-shaped key **before**
  the message is parsed, logged, or acted on.
- Components sign a **challenge**, not their state. Signing proves possession of
  a private key; it reveals nothing about the key or about wallet material.
- The verifier consumes only: public keys, signatures, hashes, counters, version
  strings, and certificate metadata. Its entire input type (`VerifyInputs`) has
  no channel for secret data.
- The device simulator (and the real device firmware contract) is only ever
  asked to produce signatures over public transcript bytes.

See `docs/protocol.md` §"Secret-free guarantee" for the message-by-message
argument, and `tests/e2e-attacks.test.ts` ("secret leak") for the executable
check.

## Why "offline" works

Everything the host needs to decide is **signed data carried with the device or
shipped in the app**:

- root public key — baked into the app;
- device certificate chain — carried by the device;
- BOM digest — signed by the CA into the attestation cert;
- policy bundle (approved firmware, revocations, required components) — shipped
  in the app and refreshed when the app updates.

No step calls the network. A revocation issued *after* the app was built cannot
reach a fully offline host until the app updates — that trade-off is intrinsic
to "must work offline" and is stated here rather than hidden.

## Future work

- **PUF-based component identity** to close limitation #1 for components that
  can carry one.
- **Transparency-log-backed policy** so an offline host can prove its policy
  bundle is not stale, via a signed freshness proof carried on the device.
- **Remote attestation** *in addition to* offline, for users who prefer
  defence-in-depth; the offline path remains the baseline.
