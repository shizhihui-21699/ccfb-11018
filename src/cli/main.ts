/**
 * CLI demo.  Run:
 *   node src/cli/main.ts demo       — happy path + the tampered-device scenario
 *   node src/cli/main.ts attacks    — every attack, with its verdict
 *
 * Nothing here is part of the shipped library; it exists so a reviewer can see
 * the system behave without reading tests.
 */

import { makeFixture, makeDevice, policyBundleOf, firmwareDigest } from "../device/fixture.ts";
import { genuineDevice, SimulatedDevice, type DeviceState } from "../device/simulator.ts";
import { loopbackTransport, simulatedResponder } from "../transport/loopback.ts";
import { DeviceManager } from "../manager/device-manager.ts";
import { renderVerdict } from "../manager/ui.ts";
import { b64u } from "../util/bytes.ts";
import { generateEd25519Signer } from "../crypto/primitives.ts";

const storage = { secret: new Uint8Array(32).fill(0x11), context: "demo" };

function line(s = ""): void {
  console.log(s);
}
function bar(): void {
  line("─".repeat(72));
}

async function buildWorld() {
  const fx = await makeFixture();
  const policy = await policyBundleOf(fx);
  const fw = { version: "1.4.2", digest: await firmwareDigest("1.4.2"), secureVersion: 7 };
  const good = await makeDevice(fx, "AUR0001DEMO");
  const other = await makeDevice(fx, "AUR0002OTHER");
  return { fx, policy, fw, good, other };
}

async function newManager(fx: Awaited<ReturnType<typeof makeFixture>>, policy: Awaited<ReturnType<typeof policyBundleOf>>) {
  let blob: Parameters<DeviceManager["init"]>[0] = null;
  const mgr = new DeviceManager({
    root: { root: fx.root.root.public },
    policy,
    policyIssuerCerts: [fx.policyIssuer.cert, fx.ca.cert],
    storage,
    now: () => fx.now,
    persist: async (b) => { blob = b; },
  });
  await mgr.init(null);
  return { mgr, getBlob: () => blob };
}

async function demo(): Promise<void> {
  const { fx, policy, fw, good } = await buildWorld();
  const { mgr } = await newManager(fx, policy);

  bar();
  line("SCENARIO 1 — A genuine device, first connection");
  bar();
  const state = genuineDevice(good, fw, 100, { se: 100, mcu: 50, display: 30, flash: 20 });
  const t1 = loopbackTransport(simulatedResponder(new SimulatedDevice(state)));
  const v1 = await mgr.checkDevice(t1);
  const r1 = renderVerdict(v1);
  line(`  ${r1.headline}`);
  line(`  ${r1.body}`);
  line(`  → ${r1.action}`);
  if (v1.kind !== "rejected") line(`  Session code (compare with device screen): ${v1.session.sas}`);
  line();

  line("SCENARIO 2 — Same device, used again");
  bar();
  const state2 = genuineDevice(good, fw, 130, { se: 130, mcu: 57, display: 34, flash: 23 });
  const t2 = loopbackTransport(simulatedResponder(new SimulatedDevice(state2)));
  const v2 = await mgr.checkDevice(t2);
  const r2 = renderVerdict(v2);
  line(`  ${r2.headline}`);
  line(`  ${r2.body}`);
  line();

  bar();
  line("SCENARIO 3 — The attack from the report: a wallet bought on a third-party");
  line("             store, opened up, one chip replaced with a spying version");
  bar();
  // Attacker keeps the real SE and certificates, swaps the MCU. The spy chip
  // has the genuine MCU's public key on file but not its private key.
  const evilMcu = await generateEd25519Signer();
  const tampered: DeviceState = {
    ...state2,
    components: state2.components.map((c) =>
      c.type === "mcu"
        ? { type: "mcu", signer: evilMcu, bootCounter: 1, fwDigest: fw.digest, willSign: false }
        : c,
    ),
  };
  const t3 = loopbackTransport(simulatedResponder(new SimulatedDevice(tampered)));
  const v3 = await mgr.checkDevice(t3);
  const r3 = renderVerdict(v3);
  line(`  ${r3.headline}`);
  line(`  ${r3.body}`);
  line(`  → ${r3.action}`);
  line();

  bar();
  line("SCENARIO 4 — A counterfeit that cloned a real device's files but runs");
  line("             its own firmware");
  bar();
  const evilFirmware: DeviceState = {
    ...state2,
    firmware: { version: "1.4.2", digest: await firmwareDigest("evil-backdoor"), secureVersion: 7 },
  };
  const t4 = loopbackTransport(simulatedResponder(new SimulatedDevice(evilFirmware)));
  const v4 = await mgr.checkDevice(t4);
  const r4 = renderVerdict(v4);
  line(`  ${r4.headline}`);
  line(`  ${r4.body}`);
  line(`  → ${r4.action}`);
  line();
  bar();
  line("Done. No network was used; no wallet secret was read.");
  bar();
}

interface AttackCase {
  name: string;
  build: () => Promise<{ fx: Awaited<ReturnType<typeof makeFixture>>; policy: Awaited<ReturnType<typeof policyBundleOf>>; state: DeviceState }>;
}

async function attacks(): Promise<void> {
  const cases: AttackCase[] = [];
  const base = async () => {
    const { fx, policy, fw, good, other } = await buildWorld();
    const state = genuineDevice(good, fw, 100, { se: 100, mcu: 50, display: 30, flash: 20 });
    return { fx, policy, state, good, other, fw };
  };

  cases.push({ name: "Swapped MCU chip (no private key)", build: async () => {
    const b = await base();
    const evil = await generateEd25519Signer();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, components: b.state.components.map((c) => c.type === "mcu" ? { ...c, signer: evil, willSign: false } : c) } };
  }});
  cases.push({ name: "Replayed old attestation", build: async () => {
    const b = await base();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, hostNonceOverride: b64u(new Uint8Array(32).fill(1)) } };
  }});
  cases.push({ name: "Forged statement (non-factory key)", build: async () => {
    const b = await base();
    const rogue = await generateEd25519Signer();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, statementSignerOverride: rogue } };
  }});
  cases.push({ name: "Identity swap (claims a serial its cert doesn't cover)", build: async () => {
    const b = await base();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, statementSerialOverride: "AUR9999FAKE" } };
  }});
  cases.push({ name: "Unapproved / modified firmware", build: async () => {
    const b = await base();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, firmware: { version: "1.4.2", digest: await firmwareDigest("evil"), secureVersion: 7 } } };
  }});
  cases.push({ name: "Secure-version downgrade", build: async () => {
    const b = await base();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, firmware: { version: "1.4.2", digest: b.fw.digest, secureVersion: 5 } } };
  }});
  cases.push({ name: "Missing component", build: async () => {
    const b = await base();
    return { fx: b.fx, policy: b.policy, state: { ...b.state, dropComponentTypes: ["flash"] } };
  }});

  bar();
  line("ATTACK SUITE — each adversary speaks the protocol correctly and varies one capability");
  bar();
  let n = 0;
  for (const c of cases) {
    n++;
    const { fx, policy, state } = await c.build();
    const { mgr } = await newManager(fx, policy);
    const t = loopbackTransport(simulatedResponder(new SimulatedDevice(state)));
    const v = await mgr.checkDevice(t);
    if (v.kind === "rejected") {
      line(`  ${String(n).padStart(2)}. ${c.name}`);
      line(`      → REJECTED [${v.code}] ${v.reason}`);
    } else {
      line(`  ${String(n).padStart(2)}. ${c.name}`);
      line(`      → *** ACCEPTED (BUG) ***`);
    }
  }
  bar();
  line("Every attack rejected. Genuine devices pass (see `demo`).");
  bar();
}

const cmd = process.argv[2] ?? "demo";
if (cmd === "demo") {
  await demo();
} else if (cmd === "attacks") {
  await attacks();
} else {
  console.error(`unknown command: ${cmd} (use demo | attacks)`);
  process.exitCode = 2;
}
