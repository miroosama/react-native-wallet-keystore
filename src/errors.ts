/**
 * Stable, cross-platform error codes.
 *
 * `USER_CANCELED` and `NOT_ENROLLED` are deliberately distinct: the first means
 * "offer the prompt again", the second means "send the user to Settings".
 * Collapsing them forces callers to guess.
 */
export type KeystoreErrorCode =
  | 'NOT_AVAILABLE'
  | 'NOT_ENROLLED'
  | 'USER_CANCELED'
  | 'USER_FALLBACK'
  | 'LOCKOUT'
  | 'LOCKOUT_PERMANENT'
  | 'SYSTEM_CANCEL'
  | 'KEY_NOT_FOUND'
  | 'KEY_ALREADY_EXISTS'
  /**
   * The wrapping key is gone and the secret is unrecoverable. Distinct from
   * every other failure because retrying cannot help: the app has to start
   * recovery from a backup. iOS surfaces this as errSecAuthFailed after an
   * enrollment change, Android as KeyPermanentlyInvalidatedException.
   */
  | 'KEY_INVALIDATED'
  | 'STORAGE_ERROR'
  /** A private key outside [1, n-1], or a digest that is not 32 bytes. */
  | 'INVALID_KEY'
  | 'UNKNOWN';

const KNOWN_CODES: ReadonlySet<string> = new Set<KeystoreErrorCode>([
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
]);

export class KeystoreError extends Error {
  readonly code: KeystoreErrorCode;

  /**
   * The raw `code` string the native layer rejected with. Retained even when it
   * is not recognized, so an unexpected platform error is still diagnosable
   * after `code` has fallen back to `'UNKNOWN'`.
   */
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
      // Assigned rather than passed to super() so this works on targets that
      // predate the ES2022 `cause` option.
      (this as { cause?: unknown }).cause = options.cause;
    }

    // Restores the prototype chain when compiled down to ES5, where extending
    // a built-in otherwise breaks `instanceof`.
    Object.setPrototypeOf(this, KeystoreError.prototype);

    // Omits this constructor from the stack, so the trace points at the caller.
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
 * Normalizes whatever the native module rejected with into a `KeystoreError`.
 *
 * React Native surfaces `reject(code, message)` as an `Error` carrying a `code`
 * property, but a JS-side failure (or a future native change) can produce
 * anything at all — so every shape has to degrade to `UNKNOWN` rather than
 * throwing while building the error.
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
