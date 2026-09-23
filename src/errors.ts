/**
 * Stable, cross-platform error codes.
 *
 * The distinctions are load-bearing: `USER_CANCELED` means re-prompt,
 * `NOT_ENROLLED` means send the user to Settings, and `KEY_INVALIDATED` means
 * the secret is gone and recovery must start. Collapsing them makes callers
 * guess.
 */
const CODES = [
  'NOT_AVAILABLE',
  'NOT_ENROLLED',
  'USER_CANCELED',
  'USER_FALLBACK',
  'LOCKOUT',
  'LOCKOUT_PERMANENT',
  'SYSTEM_CANCEL',
  'KEY_NOT_FOUND',
  'KEY_ALREADY_EXISTS',
  'KEY_INVALIDATED',
  'STORAGE_ERROR',
  'INVALID_KEY',
  'UNKNOWN',
] as const;

export type KeystoreErrorCode = (typeof CODES)[number];

const KNOWN_CODES: ReadonlySet<string> = new Set(CODES);

export class KeystoreError extends Error {
  readonly code: KeystoreErrorCode;

  /** The raw native code, kept even when `code` has fallen back to `UNKNOWN`. */
  readonly nativeCode?: string;

  constructor(
    code: KeystoreErrorCode,
    message: string,
    options?: { nativeCode?: string; cause?: unknown }
  ) {
    super(message);
    this.name = 'KeystoreError';
    this.code = code;
    this.nativeCode = options?.nativeCode;

    if (options && 'cause' in options) {
      // Assigned rather than passed to super() to support pre-ES2022 targets.
      (this as { cause?: unknown }).cause = options.cause;
    }

    // Without this, extending a built-in breaks `instanceof` once compiled to
    // ES5 — silently, and only for consumers.
    Object.setPrototypeOf(this, KeystoreError.prototype);

    const capture = (
      Error as unknown as {
        captureStackTrace?: (t: object, c?: unknown) => void;
      }
    ).captureStackTrace;
    if (typeof capture === 'function') {
      capture(this, KeystoreError);
    }
  }
}

function isKeystoreErrorCode(value: unknown): value is KeystoreErrorCode {
  return typeof value === 'string' && KNOWN_CODES.has(value);
}

/**
 * Normalizes any rejection into a `KeystoreError`.
 *
 * React Native surfaces `reject(code, message)` as an `Error` carrying `code`,
 * but a JS-side failure can produce any shape at all, so everything degrades to
 * `UNKNOWN` rather than throwing while building the error.
 */
export function toKeystoreError(value: unknown): KeystoreError {
  if (value instanceof KeystoreError) {
    return value;
  }

  const raw = (value as { code?: unknown } | null | undefined)?.code;
  const message =
    (value as { message?: unknown } | null | undefined)?.message ??
    'The keystore operation failed.';

  return new KeystoreError(
    isKeystoreErrorCode(raw) ? raw : 'UNKNOWN',
    typeof message === 'string' ? message : String(message),
    {
      nativeCode: typeof raw === 'string' ? raw : undefined,
      cause: value,
    }
  );
}
