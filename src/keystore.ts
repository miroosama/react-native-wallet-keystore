import NativeWalletKeystore from './NativeWalletKeystore';
import { KeystoreError, toKeystoreError } from './errors';

/**
 * iOS reports the exact modality. Android can only report which biometric
 * *hardware* is present, not which modality is enrolled, so it falls back to
 * the generic `'biometric'` when more than one is available.
 */
export type BiometryType =
  | 'faceId'
  | 'touchId'
  | 'opticId'
  | 'fingerprint'
  | 'face'
  | 'iris'
  | 'biometric'
  | 'none';

export type AuthPolicy = 'biometricOnly' | 'biometricOrPasscode' | 'none';

export const DEFAULT_AUTH_POLICY: AuthPolicy = 'biometricOrPasscode';

const BIOMETRY_TYPES: ReadonlySet<string> = new Set<BiometryType>([
  'faceId',
  'touchId',
  'opticId',
  'fingerprint',
  'face',
  'iris',
  'biometric',
  'none',
]);

/**
 * Which biometric modality the device hardware supports.
 *
 * Reports the hardware modality even when nothing is enrolled, so callers can
 * write "Enable Face ID in Settings" rather than a generic message. Enrollment
 * state comes from {@link authenticate}, which rejects with `NOT_ENROLLED`.
 *
 * Resolves `'none'` when there is no biometric hardware; does not reject.
 */
export async function getBiometryType(): Promise<BiometryType> {
  const type = await NativeWalletKeystore.getBiometryType();
  // An unrecognized value means a newer native layer than this JS — degrade to
  // the generic type rather than leaking a string that isn't in the union.
  if (!BIOMETRY_TYPES.has(type)) {
    return 'biometric';
  }
  return type as BiometryType;
}

/**
 * Prompts for device-owner authentication.
 *
 * @param reason Shown to the user as the prompt's message. Must be non-empty —
 *   iOS raises for an empty `localizedReason`, so it is rejected here first for
 *   a consistent error across platforms.
 * @param policy Defaults to `'biometricOrPasscode'`. `'none'` resolves `true`
 *   without prompting.
 *
 * Resolves `true` on success. Never resolves `false` — every failure rejects
 * with a {@link KeystoreError} so a missed `await` cannot read as success.
 *
 * @throws {KeystoreError}
 */
export async function authenticate(
  reason: string,
  policy: AuthPolicy = DEFAULT_AUTH_POLICY
): Promise<boolean> {
  try {
    if (typeof reason !== 'string' || reason.trim() === '') {
      throw new KeystoreError(
        'UNKNOWN',
        'A non-empty `reason` is required to authenticate.'
      );
    }
    return await NativeWalletKeystore.authenticate(reason, policy);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Whether the wrapping key survives a change to the device's biometric
 * enrollment.
 *
 * Deliberately orthogonal to {@link AuthPolicy}: *which* authenticators are
 * accepted is a separate question from *when the key is destroyed*. Binding
 * them — letting `'biometricOnly'` imply invalidation, as several libraries do
 * — means a user adding a fingerprint silently destroys their wallet key. That
 * has to be an explicit opt-in.
 *
 * `'onEnrollmentChange'` is the stronger guarantee and the more dangerous
 * default, so the default is `'never'`.
 */
export type InvalidationPolicy = 'onEnrollmentChange' | 'never';

export const DEFAULT_INVALIDATION_POLICY: InvalidationPolicy = 'never';

const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})+$/;

function assertKeyId(keyId: string): void {
  if (typeof keyId !== 'string' || keyId.trim() === '') {
    throw new KeystoreError('UNKNOWN', 'A non-empty `keyId` is required.');
  }
}

/**
 * Stores a secret encrypted under a hardware-bound wrapping key.
 *
 * The secret is hex because the bridge cannot carry bytes, and because a hex
 * string is unambiguous about length in a way a UTF-8 string is not.
 *
 * Storing needs no authentication — only {@link getSecret} prompts. That
 * asymmetry is deliberate: it lets a wallet be provisioned in the background
 * and only demand the user at the moment of use.
 *
 * @throws {KeystoreError} `KEY_ALREADY_EXISTS` if `keyId` is taken.
 */
export async function storeSecret(
  keyId: string,
  secretHex: string,
  options: {
    policy?: AuthPolicy;
    invalidation?: InvalidationPolicy;
  } = {}
): Promise<void> {
  try {
    assertKeyId(keyId);

    // Validated here rather than natively so the two platforms cannot disagree
    // about what counts as hex, and so an odd-length string fails before it is
    // half-parsed into a key.
    if (typeof secretHex !== 'string' || !HEX_PATTERN.test(secretHex)) {
      throw new KeystoreError(
        'UNKNOWN',
        '`secretHex` must be a non-empty, even-length hex string.'
      );
    }

    await NativeWalletKeystore.storeSecret(
      keyId,
      secretHex,
      options.policy ?? DEFAULT_AUTH_POLICY,
      options.invalidation ?? DEFAULT_INVALIDATION_POLICY
    );
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Authenticates and returns the stored secret as hex.
 *
 * Unlike {@link authenticate}, the prompt here is not a check this library
 * performs and then trusts — the wrapping key is unusable until the OS has
 * validated the user, so a compromised JS bundle cannot skip it.
 *
 * The returned string lands in the JS heap, where it cannot be reliably zeroed
 * and persists until garbage collection. That is inherent to crossing the
 * bridge, and is why `signDigest` will exist: so the common path never surfaces
 * the key to JS at all. Prefer this only for user-initiated export.
 *
 * @throws {KeystoreError} `KEY_NOT_FOUND`, `KEY_INVALIDATED`, or any auth code.
 */
export async function getSecret(
  keyId: string,
  reason: string
): Promise<string> {
  try {
    assertKeyId(keyId);

    if (typeof reason !== 'string' || reason.trim() === '') {
      throw new KeystoreError(
        'UNKNOWN',
        'A non-empty `reason` is required to read a secret.'
      );
    }

    return await NativeWalletKeystore.getSecret(keyId, reason);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/** Whether a secret is stored under `keyId`. Does not authenticate. */
export async function hasSecret(keyId: string): Promise<boolean> {
  try {
    assertKeyId(keyId);
    return await NativeWalletKeystore.hasSecret(keyId);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Removes the secret and its wrapping key. Idempotent — deleting a `keyId` that
 * is not present resolves rather than rejecting, so teardown paths do not have
 * to guard.
 */
export async function deleteSecret(keyId: string): Promise<void> {
  try {
    assertKeyId(keyId);
    await NativeWalletKeystore.deleteSecret(keyId);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

// -----------------------------------------------------------------------------
// secp256k1 keys and signing
// -----------------------------------------------------------------------------

/** Uncompressed SEC1 public key: `0x04` followed by 64 bytes. */
export type PublicKeyHex = `0x${string}`;

/** 65-byte Ethereum signature: `r || s || v`, with `v` 27 or 28. */
export type SignatureHex = `0x${string}`;

const HEX_32_BYTES = /^(?:0x)?[0-9a-fA-F]{64}$/;

function strip0x(value: string): string {
  return value.startsWith('0x') || value.startsWith('0X')
    ? value.slice(2)
    : value;
}

function prefix0x(value: string): `0x${string}` {
  return (value.startsWith('0x') ? value : `0x${value}`) as `0x${string}`;
}

/**
 * Generates a secp256k1 keypair in hardware-wrapped storage.
 *
 * Entropy comes from the platform CSPRNG — `SecRandomCopyBytes` on iOS,
 * `SecureRandom` on Android — never from JavaScript, whose PRNG is not
 * cryptographically secure and whose state is observable to the bundle.
 *
 * The private key never crosses the bridge. Only the public key is returned.
 *
 * @returns The uncompressed public key. Derive the address with viem's
 *   `publicKeyToAddress`.
 */
export async function generateKey(
  keyId: string,
  options: { policy?: AuthPolicy; invalidation?: InvalidationPolicy } = {}
): Promise<PublicKeyHex> {
  try {
    assertKeyId(keyId);
    const publicKey = await NativeWalletKeystore.generateKey(
      keyId,
      options.policy ?? DEFAULT_AUTH_POLICY,
      options.invalidation ?? DEFAULT_INVALIDATION_POLICY
    );
    return prefix0x(publicKey);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Imports an existing secp256k1 private key.
 *
 * @throws {KeystoreError} `INVALID_KEY` if the key is not in [1, n-1]. Zero and
 *   values at or above the curve order are not merely malformed — they produce
 *   signatures that leak or verify against nothing, so they are rejected rather
 *   than clamped.
 */
export async function importPrivateKey(
  keyId: string,
  privateKeyHex: string,
  options: { policy?: AuthPolicy; invalidation?: InvalidationPolicy } = {}
): Promise<PublicKeyHex> {
  try {
    assertKeyId(keyId);

    if (
      typeof privateKeyHex !== 'string' ||
      !HEX_32_BYTES.test(privateKeyHex)
    ) {
      throw new KeystoreError(
        'INVALID_KEY',
        'A private key must be exactly 32 bytes of hex.'
      );
    }

    // The range check itself stays native, where the curve order is already
    // available and constant-time comparison is possible.
    const publicKey = await NativeWalletKeystore.importPrivateKey(
      keyId,
      strip0x(privateKeyHex),
      options.policy ?? DEFAULT_AUTH_POLICY,
      options.invalidation ?? DEFAULT_INVALIDATION_POLICY
    );
    return prefix0x(publicKey);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/** The uncompressed public key. Does not authenticate. */
export async function getPublicKey(keyId: string): Promise<PublicKeyHex> {
  try {
    assertKeyId(keyId);
    return prefix0x(await NativeWalletKeystore.getPublicKey(keyId));
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Authenticates, then signs a 32-byte digest.
 *
 * Only a digest crosses the boundary — never a message, never a transaction.
 * Keccak and all EIP-191/712/155 encoding stay in JS, which keeps this module
 * curve-specific but chain-agnostic, and keeps a hashing implementation (and
 * the SHA3-vs-Keccak padding trap) out of the native layer entirely.
 *
 * @returns 65 bytes, `r || s || v`. `s` is low-s normalized per EIP-2 and `v`
 *   is 27/28, so the output matches viem byte-for-byte.
 */
export async function signDigest(
  keyId: string,
  digestHex: string,
  reason: string
): Promise<SignatureHex> {
  try {
    assertKeyId(keyId);

    if (typeof digestHex !== 'string' || !HEX_32_BYTES.test(digestHex)) {
      throw new KeystoreError(
        'INVALID_KEY',
        'A digest must be exactly 32 bytes of hex. Hash the message in JS first.'
      );
    }

    if (typeof reason !== 'string' || reason.trim() === '') {
      throw new KeystoreError(
        'UNKNOWN',
        'A non-empty `reason` is required to sign.'
      );
    }

    return prefix0x(
      await NativeWalletKeystore.signDigest(keyId, strip0x(digestHex), reason)
    );
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Authenticates, then returns the raw private key.
 *
 * Intended for user-initiated backup only. The returned string lands in the JS
 * heap where it cannot be zeroed, so the everyday path should be
 * {@link signDigest}, which never surfaces the key at all.
 */
export async function exportPrivateKey(
  keyId: string,
  reason: string
): Promise<string> {
  try {
    assertKeyId(keyId);

    if (typeof reason !== 'string' || reason.trim() === '') {
      throw new KeystoreError(
        'UNKNOWN',
        'A non-empty `reason` is required to export a private key.'
      );
    }

    return prefix0x(await NativeWalletKeystore.exportPrivateKey(keyId, reason));
  } catch (error) {
    throw toKeystoreError(error);
  }
}
