/**
 * Human-readable rendering of verdicts and failures.
 *
 * The mapping from machine `ErrorCode` to user-facing text lives here, in one
 * place, so security logic never depends on strings.  Messages are deliberately
 * specific: "component 'mcu' failed live challenge" is actionable, "verification
 * failed" is not.  Every rejected verdict tells the user what happened and what
 * to do — and never blames them for something the UI should have prevented.
 */

import type { ErrorCode } from "../util/errors.ts";
import type { Verdict } from "../manager/device-manager.ts";

export interface RenderedVerdict {
  readonly headline: string;
  readonly body: string;
  readonly action: string;
  readonly severity: "ok" | "warning" | "critical";
}

const MESSAGES: Record<ErrorCode, { body: string; action: string; severity: "warning" | "critical" }> = {
  TRANSPORT_ERROR: {
    body: "The device stopped responding during verification.",
    action: "Unplug and reconnect the device, then try again. Do not enter your recovery phrase anywhere.",
    severity: "warning",
  },
  MESSAGE_TOO_LARGE: {
    body: "The device sent more data than the protocol allows.",
    action: "This is not normal. Do not use the device. Report it to support.",
    severity: "critical",
  },
  BAD_FRAMING: {
    body: "The device sent a malformed message.",
    action: "Do not use the device. Report it to support.",
    severity: "critical",
  },
  UNEXPECTED_MESSAGE: {
    body: "The device sent a message out of order.",
    action: "Disconnect the device and contact support.",
    severity: "critical",
  },
  PROTOCOL_VERSION_UNSUPPORTED: {
    body: "The device speaks an incompatible protocol version.",
    action: "Update the desktop app. If it persists, the device firmware may be unofficial.",
    severity: "warning",
  },
  MALFORMED_MESSAGE: {
    body: "The device sent data that does not match the expected format.",
    action: "This can indicate a counterfeit or tampered device. Do not use it for assets.",
    severity: "critical",
  },
  CANONICALIZATION_ERROR: {
    body: "The device's response was encoded ambiguously — a tell-tale sign of tampering.",
    action: "Do not use the device for assets. Contact support with this code.",
    severity: "critical",
  },
  FIELD_OUT_OF_RANGE: {
    body: "A value in the device's response is outside the allowed range.",
    action: "Do not use the device. Report it to support.",
    severity: "critical",
  },
  CERT_PARSE_ERROR: {
    body: "The device's identity certificate could not be read.",
    action: "The device may be counterfeit. Do not use it for assets.",
    severity: "critical",
  },
  CERT_SIGNATURE_INVALID: {
    body: "The device's certificate signature is invalid.",
    action: "This device was not issued by our factory. Do not use it.",
    severity: "critical",
  },
  CERT_CHAIN_INCOMPLETE: {
    body: "The device's certificate does not chain to our factory root.",
    action: "This device is not genuine or its identity was altered. Do not use it.",
    severity: "critical",
  },
  CERT_CHAIN_UNTRUSTED: {
    body: "The device presented a certificate from an unknown authority.",
    action: "This device is not genuine. Do not use it.",
    severity: "critical",
  },
  CERT_EXPIRED: {
    body: "The device's certificate has expired.",
    action: "Check the app is up to date. If it persists, contact support.",
    severity: "warning",
  },
  CERT_NOT_YET_VALID: {
    body: "The device's certificate is not yet valid — check your computer's clock.",
    action: "Set the correct date/time and retry. If it persists, contact support.",
    severity: "warning",
  },
  CERT_KEY_USAGE: {
    body: "A certificate is being used for a purpose it was not issued for.",
    action: "This indicates tampering. Do not use the device.",
    severity: "critical",
  },
  CERT_SERIAL_MISMATCH: {
    body: "The device's parts are certified for a different unit.",
    action: "This device has been reassembled from mixed parts. Do not use it.",
    severity: "critical",
  },
  DEVICE_MISMATCH: {
    body: "This device does not match the identity we recorded for it.",
    action: "If you did not replace the device, it may have been swapped. Do not use it.",
    severity: "critical",
  },
  UNPINNED_DEVICE: {
    body: "This device has not been verified on this computer before.",
    action: "Review the details and confirm it is the device you are holding.",
    severity: "warning",
  },
  SERIAL_NOT_ISSUED: {
    body: "This serial number was never issued by our factory.",
    action: "The device is counterfeit. Do not use it.",
    severity: "critical",
  },
  CHALLENGE_MISMATCH: {
    body: "The device answered an old or different challenge — a replay.",
    action: "Do not use the device. Reconnect and retry; if it repeats, contact support.",
    severity: "critical",
  },
  TRANSCRIPT_MISMATCH: {
    body: "Parts of the device's signed response disagree with each other.",
    action: "Do not use the device. Report it to support.",
    severity: "critical",
  },
  STATEMENT_SIGNATURE_INVALID: {
    body: "The device's signed identity statement is not valid.",
    action: "Do not use the device for assets.",
    severity: "critical",
  },
  FRESHNESS_MISMATCH: {
    body: "The device's proof is not fresh for this connection.",
    action: "Reconnect and retry. If it repeats, do not use the device.",
    severity: "critical",
  },
  FIRMWARE_NOT_ALLOWED: {
    body: "The device is running firmware we did not approve.",
    action: "Do not use the device for assets. It may be modified. Contact support.",
    severity: "critical",
  },
  FIRMWARE_DIGEST_INVALID: {
    body: "The firmware measurement is malformed.",
    action: "Do not use the device. Report it to support.",
    severity: "critical",
  },
  FIRMWARE_ROLLBACK: {
    body: "The device is running older, less secure firmware than before.",
    action: "This is a downgrade attack. Do not use the device; update and retry.",
    severity: "critical",
  },
  SECURE_VERSION_TOO_LOW: {
    body: "The device's security version is lower than the approved firmware requires.",
    action: "A downgrade was attempted. Do not use the device for assets.",
    severity: "critical",
  },
  COUNTER_ROLLBACK: {
    body: "The device's tamper counter went backwards.",
    action: "This indicates a clone or rollback attack. Do not use the device.",
    severity: "critical",
  },
  BOM_DIGEST_MISMATCH: {
    body: "The device's internal components do not match what we built for it.",
    action: "A component may have been swapped. Do not use the device for assets.",
    severity: "critical",
  },
  BOM_INCOMPLETE: {
    body: "The device did not report all of its required components.",
    action: "A component is missing or unresponsive. Do not use the device.",
    severity: "critical",
  },
  COMPONENT_NOT_TRUSTED: {
    body: "One of the device's components is not certified.",
    action: "A component was swapped. Do not use the device for assets.",
    severity: "critical",
  },
  COMPONENT_SERIAL_MISMATCH: {
    body: "A component is certified for a different device.",
    action: "The device was reassembled. Do not use it.",
    severity: "critical",
  },
  COMPONENT_ATTESTATION_INVALID: {
    body: "A component failed its live identity challenge.",
    action: "A component may have been replaced or cloned. Do not use the device for assets.",
    severity: "critical",
  },
  DEVICE_REVOKED: {
    body: "This device has been recalled or reported compromised.",
    action: "Stop using it immediately and contact support to arrange a replacement.",
    severity: "critical",
  },
  KEY_REVOKED: {
    body: "A key in this device has been revoked by the factory.",
    action: "The device's keys may be compromised. Do not use it.",
    severity: "critical",
  },
  SESSION_KEY_UNCONFIRMED: {
    body: "The device could not prove it holds the agreed session secret.",
    action: "Possible man-in-the-middle. Reconnect; if it repeats, contact support.",
    severity: "critical",
  },
  SESSION_MAC_INVALID: {
    body: "A message failed its integrity check.",
    action: "Do not proceed. Reconnect and retry.",
    severity: "critical",
  },
  RELAY_SUSPECTED: {
    body: "The code shown on the device did not match this computer's code.",
    action: "Someone may be relaying your connection. Stop and contact support.",
    severity: "critical",
  },
  USER_PRESENCE_REQUIRED: {
    body: "We did not see you press the button on the device.",
    action: "Press the button on your device when prompted and try again.",
    severity: "warning",
  },
  USER_PRESENCE_INVALID: {
    body: "The device's confirmation of your button press is not valid.",
    action: "Do not proceed with this operation. Reconnect and retry.",
    severity: "critical",
  },
  ALLOWLIST_EXPIRED: {
    body: "The app's approval list is out of date.",
    action: "Update the desktop app and retry. The device has not been rejected.",
    severity: "warning",
  },
  ALLOWLIST_SIGNATURE_INVALID: {
    body: "The app's approval list failed its signature check.",
    action: "The app may be tampered with. Reinstall from an official source.",
    severity: "critical",
  },
  TRUST_STORE_CORRUPT: {
    body: "The saved device-verification data is damaged.",
    action: "The app will re-verify all devices. If this repeats, reinstall the app.",
    severity: "warning",
  },
  TRUST_STORE_SEAL_INVALID: {
    body: "The saved device-verification data failed its integrity check.",
    action: "Someone may have tampered with app data. Reinstall and re-verify devices.",
    severity: "critical",
  },
  TRUST_STORE_REPLAY: {
    body: "The saved device-verification data was rolled back to an older copy.",
    action: "Someone may be hiding a tampered device. Do not proceed; reinstall and re-verify.",
    severity: "critical",
  },
  POLICY_VIOLATION: {
    body: "This device's configuration violates our security policy.",
    action: "Do not use the device for assets. Contact support.",
    severity: "critical",
  },
  INTERNAL_ERROR: {
    body: "Verification could not be completed due to an internal error.",
    action: "Do not proceed with asset operations. Restart the app and retry.",
    severity: "critical",
  },
};

export function renderVerdict(v: Verdict): RenderedVerdict {
  if (v.kind === "genuine") {
    return {
      headline: "Genuine device",
      body: `This is an authentic ${v.model} (serial ${v.serial}), unmodified, running approved firmware.`,
      action: "You're all set.",
      severity: "ok",
    };
  }
  if (v.kind === "authentic-but-unpinned") {
    return {
      headline: "Genuine device — now remembered",
      body: `This is an authentic ${v.model} (serial ${v.serial}). We've saved its identity for future checks.`,
      action: "Compare the code on the device screen with the one shown here to rule out a relay.",
      severity: "ok",
    };
  }
  const m = MESSAGES[v.code] ?? MESSAGES.INTERNAL_ERROR;
  return {
    headline: v.code === "USER_PRESENCE_REQUIRED" ? "Button press needed" : "DO NOT USE THIS DEVICE",
    body: `${m.body} (${v.code})`,
    action: m.action,
    severity: m.severity,
  };
}

export function formatSas(sas: string): string {
  return sas;
}
