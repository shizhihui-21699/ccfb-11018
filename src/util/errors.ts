/**
 * Typed error taxonomy.
 *
 * Every rejection the verifier can emit carries a stable machine-readable
 * `code`.  The UI maps codes to human messages; security logic never depends
 * on error strings.  Codes are stable API: never renumber them.
 */

export type ErrorCode =
  // transport / framing
  | "TRANSPORT_ERROR"
  | "MESSAGE_TOO_LARGE"
  | "BAD_FRAMING"
  | "UNEXPECTED_MESSAGE"
  | "PROTOCOL_VERSION_UNSUPPORTED"
  // structural / decoding
  | "MALFORMED_MESSAGE"
  | "CANONICALIZATION_ERROR"
  | "FIELD_OUT_OF_RANGE"
  // identity / chain
  | "CERT_PARSE_ERROR"
  | "CERT_SIGNATURE_INVALID"
  | "CERT_CHAIN_INCOMPLETE"
  | "CERT_CHAIN_UNTRUSTED"
  | "CERT_EXPIRED"
  | "CERT_NOT_YET_VALID"
  | "CERT_KEY_USAGE"
  | "CERT_SERIAL_MISMATCH"
  | "DEVICE_MISMATCH"
  | "UNPINNED_DEVICE"
  | "SERIAL_NOT_ISSUED"
  // attestation content
  | "CHALLENGE_MISMATCH"
  | "TRANSCRIPT_MISMATCH"
  | "STATEMENT_SIGNATURE_INVALID"
  | "FRESHNESS_MISMATCH"
  | "FIRMWARE_NOT_ALLOWED"
  | "FIRMWARE_DIGEST_INVALID"
  | "FIRMWARE_ROLLBACK"
  | "SECURE_VERSION_TOO_LOW"
  | "COUNTER_ROLLBACK"
  | "BOM_DIGEST_MISMATCH"
  | "BOM_INCOMPLETE"
  | "COMPONENT_NOT_TRUSTED"
  | "COMPONENT_SERIAL_MISMATCH"
  | "COMPONENT_ATTESTATION_INVALID"
  | "DEVICE_REVOKED"
  | "KEY_REVOKED"
  // session / liveness / relay
  | "SESSION_KEY_UNCONFIRMED"
  | "SESSION_MAC_INVALID"
  | "RELAY_SUSPECTED"
  | "USER_PRESENCE_REQUIRED"
  | "USER_PRESENCE_INVALID"
  // policy / store
  | "ALLOWLIST_EXPIRED"
  | "ALLOWLIST_SIGNATURE_INVALID"
  | "TRUST_STORE_CORRUPT"
  | "TRUST_STORE_SEAL_INVALID"
  | "TRUST_STORE_REPLAY"
  | "POLICY_VIOLATION"
  | "INTERNAL_ERROR";

export class AttestationError extends Error {
  readonly code: ErrorCode;
  readonly detail?: Readonly<Record<string, unknown>>;

  constructor(code: ErrorCode, message: string, detail?: Readonly<Record<string, unknown>>) {
    super(message);
    this.name = "AttestationError";
    this.code = code;
    this.detail = detail;
  }
}

export function fail(code: ErrorCode, message: string, detail?: Readonly<Record<string, unknown>>): never {
  throw new AttestationError(code, message, detail);
}

export function isAttestationError(e: unknown): e is AttestationError {
  return e instanceof AttestationError;
}
