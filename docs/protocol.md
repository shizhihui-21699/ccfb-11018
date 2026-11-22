# Protocol specification

Version 1. All messages are **canonical JSON** (see §Encoding). Crypto is
WebCrypto: Ed25519 signatures, X25519 ECDH, HKDF-SHA256, HMAC-SHA256,
AES-256-GCM, SHA-256.

## 1. Trust hierarchy

```
root (Ed25519, offline; public key ships in the app)
 └─ device-ca (Ed25519, intermediate)
     ├─ attestation cert   role=attestation, carries serial, model, bomDigest
     ├─ component certs     role=component, one per non-SE component (type, serial, model)
     └─ policy cert         role=policy, signs the firmware/revocation bundle
```

The SE's identity **is** its attestation certificate; it has no separate
component cert. The factory-computed `bomDigest` covers the SE key plus every
component key and is signed into the attestation cert by the CA — so the
expected set of parts for a serial is authenticated by the factory, not by the
device.

## 2. Handshake

```
Host                                          Device
 │  HELLO {sessionId,hostNonce,hostEphPub,t} ─▶ │
 │ ◀─ ATTEST {certBundle,statement,statementSig} │
 │  CONFIRM {transcriptHash,hostConfirm} ─────▶ │
 │ ◀─ READY {transcriptHash,deviceConfirm}       │
```

- `hostNonce`, `deviceNonce`: 32 random bytes, fresh per connection.
- `hostEphPub`, `deviceEphPub`: X25519 public keys, fresh per connection.
- `transcriptHash = H("statement-transcript/v1", statement-minus-signatures)`.

### 2.1 HELLO

```
{ v:1, kind:"hello", sessionId: b64u(16), hostNonce: b64u(32),
  hostEphPub: b64u(32), hostTime: int }
```

### 2.2 ATTEST

```
{ v:1, kind:"attest", sessionId, hostNonce, deviceNonce: b64u(32),
  deviceEphPub: b64u(32), certBundle: [cert...], statement: {...},
  statementSig: b64u(64) }
```

`statement`:

```
{ v:1, kind:"statement",
  serial, model,
  attestationPub: b64u(32),            // raw SE public key
  sessionId, hostNonce, deviceNonce,
  hostEphPub: b64u(32), deviceEphPub: b64u(32),
  firmware: { version, digest: b64u(32), secureVersion },
  seCounter: u32,
  batch,
  components: [ { type, pub: b64u(32), challengeSig: b64u(64),
                  bootCounter: u32, fwDigest: b64u(32) } ] }
```

`statementSig` is Ed25519 by the SE attestation key over
`"statement/v1\0" || canonical(statement)`.

Each component's `challengeSig` is Ed25519 by **that component's own** key over
`transcriptHash`. The SE's outer signature covers the entire statement,
including every `challengeSig`, so the component list cannot be edited without
breaking the SE signature, and a component cannot be swapped without failing
its own `challengeSig`.

### 2.3 CONFIRM / READY

Both carry `transcriptHash` and a 32-byte HMAC key-confirmation value under
direction-specific keys derived from the ECDH secret. A party that cannot
compute them did not complete the ECDH.

## 3. Session key schedule

From `S = X25519(hostEph, deviceEph)` and
`salt = "session-salt/v1" || hostEphPub || deviceEphPub`:

| key | derivation | use |
|-----|-----------|-----|
| `hostConfirmKey` | HKDF(S, salt, "session/v1/host-to-device-confirm") | CONFIRM |
| `deviceConfirmKey` | HKDF(S, salt, "session/v1/device-to-host-confirm") | READY |
| `hostRecordKey` | HKDF(S, salt, "session/v1/host-to-device-record") | session MACs |
| `deviceRecordKey` | HKDF(S, salt, "session/v1/device-to-host-record") | session MACs |
| SAS | HKDF(hostConfirm‖deviceConfirm, salt, "session/v1/sas") → 20 digits | human compare |

The SAS is shown on both the host and the device's own trusted display. A
transparent relay makes them match (and the user is talking to the device in
hand); a re-keying relay makes them differ → `RELAY_SUSPECTED`.

## 4. Presence (anti-relay, high-value ops)

`presence` challenge is `{sessionId, transcriptHash, presenceNonce,
displayCode}`; the device shows `displayCode` and requires a **physical button
press** before the SE signs `presence-response {presenceNonce, pressed,
displayCode}`. The signature is verified under the **pinned** SE key and is
bound to this session's transcript. An unattended remote relay has no human to
press, and a press from another session fails the nonce/transcript binding.

## 5. Verifier decision order

Exact order in `src/attestation/verifier.ts`:

1. session id + host nonce echo; envelope↔statement agreement
2. certificate chain to pinned root, validity windows
3. leaf is an attestation cert with serial/model/bomDigest; statement agrees
4. SE signature over the statement
5. identity: statement key == cert key; component keys present
6. BOM recompute `{se + components}` == CA-signed `bomDigest`
7. per-component live challenge signature
8. policy: model, expiry, component set, approved firmware + secure version,
   serial/key revocation
9. rollback vs. pinned counters / secure version / **policy version** / policy
   version (global high-water mark + per-device pin)
10. user-presence requirement reported to caller; SAS acknowledgment gate when
    the host supplies `acknowledgeSas`

## 6. Secret-free guarantee

The signed and unsigned message grammars contain **no field that can hold or
carry** a seed, entropy, mnemonic, xprv/xpriv, PIN, passphrase, or any derivative
thereof. Enforced two ways:

- **Closed schemas**: every parser calls `onlyKeys(...)` with an exact field
  list; unknown fields are `MALFORMED_MESSAGE`.
- **Value walk**: `assertNoSecretFields` rejects any inbound object containing a
  secret-shaped key *before* parsing, so even a device trying to push secrets
  into a nested value is refused with `POLICY_VIOLATION`.

Signing is over public challenge bytes only. Possession of a private key is
proven by producing a signature, which reveals nothing about the key or wallet.

## 7. Encoding rules (canonical JSON)

- UTF-8, no BOM, no insignificant whitespace.
- Object keys sorted by UTF-16 code units; the parser rejects out-of-order keys.
- Numbers: safe integers only; floats/exponents rejected.
- Byte fields: unpadded base64url; non-canonical encodings rejected.
- Duplicate keys rejected; `__proto__`/`constructor`/`prototype` rejected.
- **Round-trip rule**: `parseCanonical(x)` must re-serialize to exactly `x`, else
  `CANONICALIZATION_ERROR`. This eliminates "two encodings, one signature".

## 8. Error codes (stable API)

See `src/util/errors.ts` for the full list. UI text lives in
`src/manager/ui.ts`; security logic never branches on message strings.
