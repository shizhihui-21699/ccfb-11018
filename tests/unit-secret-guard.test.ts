import test from "node:test";
import assert from "node:assert/strict";

import { assertNoSecretFields } from "../src/protocol/messages.ts";
import { describeFailure } from "../src/manager/verify.ts";

test("secret guard: rejects a top-level secret-shaped field", () => {
  let err: unknown;
  try { assertNoSecretFields({ mnemonic: "abandon abandon" }); } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "POLICY_VIOLATION");
});

test("secret guard: rejects a secret-shaped field nested in an array", () => {
  let err: unknown;
  try { assertNoSecretFields({ components: [{ type: "se", seed: "00ff" }] }); } catch (e) { err = e; }
  assert.equal(describeFailure(err).code, "POLICY_VIOLATION");
});

test("secret guard: rejects many common spellings", () => {
  for (const key of ["seed", "mnemonic", "mnemonicPhrase", "entropy", "xprv", "xpriv", "privateKey", "passphrase", "pin", "password", "recovery", "secret", "masterKey"]) {
    let err: unknown;
    try { assertNoSecretFields({ [key]: "x" }); } catch (e) { err = e; }
    assert.equal(describeFailure(err).code, "POLICY_VIOLATION", `should reject '${key}'`);
  }
});

test("secret guard: allows ordinary protocol fields", () => {
  assert.doesNotThrow(() =>
    assertNoSecretFields({
      v: 1,
      kind: "attest",
      sessionId: "abc",
      firmware: { version: "1.4.2", digest: "xx", secureVersion: 7 },
      components: [{ type: "se", pub: "yy", challengeSig: "zz", bootCounter: 3 }],
    }),
  );
});

test("secret guard: handles nulls and primitives safely", () => {
  assert.doesNotThrow(() => assertNoSecretFields(null));
  assert.doesNotThrow(() => assertNoSecretFields(42));
  assert.doesNotThrow(() => assertNoSecretFields("plain string"));
});
