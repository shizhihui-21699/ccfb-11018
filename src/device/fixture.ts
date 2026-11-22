/**
 * A complete, self-contained factory + fleet for tests and the CLI demo.
 *
 * Provisioning is deterministic in structure but uses fresh random keys each
 * call — tests that need stable inputs set the clock explicitly.
 */

import {
  createDeviceCa,
  createPolicyIssuer,
  createRoot,
  provisionDevice,
  issuePolicy,
  type DeviceCaMaterial,
  type DeviceMaterial,
  type PolicyIssuer,
  type RootMaterial,
} from "../device/factory.ts";
import type { ModelPolicy } from "../trust/policy.ts";
import { digestOf } from "../crypto/primitives.ts";
import { b64u } from "../util/bytes.ts";
import type { ComponentType } from "../trust/certs.ts";

export const DEFAULT_MODEL = "AURUM-X1";
export const DEFAULT_BATCH = "B2026Q1";
export const ALL_COMPONENTS: ReadonlyArray<ComponentType> = ["se", "mcu", "display", "flash"];

export interface Fixture {
  readonly root: RootMaterial;
  readonly ca: DeviceCaMaterial;
  readonly policyIssuer: PolicyIssuer;
  readonly policy: ModelPolicy;
  readonly now: number;
}

/** A fake but stable firmware digest for a version string. */
export async function firmwareDigest(version: string): Promise<string> {
  return b64u(await digestOf("test-firmware/v1", { version }));
}

export async function makeFixture(opts?: {
  now?: number;
  firmwareVersion?: string;
  secureVersion?: number;
}): Promise<Fixture> {
  const now = opts?.now ?? 1_780_000_000; // 2026-05-27 UTC
  const version = opts?.firmwareVersion ?? "1.4.2";
  const secureVersion = opts?.secureVersion ?? 7;

  const root = await createRoot();
  const ca = await createDeviceCa(root, now);
  const policyIssuer = await createPolicyIssuer(root, ca, now);

  const fwDigest = await firmwareDigest(version);

  const policy: ModelPolicy = {
    model: DEFAULT_MODEL,
    issuedAt: now - 86400,
    notAfter: now + 365 * 86400,
    policyVersion: 12,
    firmware: [
      { version: "1.4.0", digest: await firmwareDigest("1.4.0"), secureVersion: 6, approved: false },
      { version, digest: fwDigest, secureVersion, approved: true },
      { version: "1.5.0-beta.1", digest: await firmwareDigest("1.5.0-beta.1"), secureVersion: 8, approved: false },
    ],
    requiredComponents: ALL_COMPONENTS,
    revokedSerials: [],
    revokedKeyIds: [],
  };

  return { root, ca, policyIssuer, policy, now };
}

export async function makeDevice(
  fx: Fixture,
  serial: string,
  opts?: {
    components?: ReadonlyArray<ComponentType>;
    certValidityDays?: number;
    model?: string;
  },
): Promise<DeviceMaterial> {
  return provisionDevice(fx.root, fx.ca, {
    serial,
    model: opts?.model ?? DEFAULT_MODEL,
    batch: DEFAULT_BATCH,
    now: fx.now,
    components: opts?.components ?? ALL_COMPONENTS,
    certValidityDays: opts?.certValidityDays,
  });
}

export async function policyBundleOf(fx: Fixture): Promise<Awaited<ReturnType<typeof issuePolicy>>> {
  return issuePolicy(fx.policyIssuer, [fx.policy]);
}
