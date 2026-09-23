import NativeWalletKeystore from './NativeWalletKeystore';
import { KeystoreError, toKeystoreError } from './errors';

/**
 * Android reports which biometric *hardware* exists, not which modality is
 * enrolled, so it returns `'biometric'` when more than one is present.
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

export type AuthPolicy = 'biometricOnly' | 'biometricOrPasscode';

/**
 * Whether the wrapping key is destroyed when biometric enrollment changes.
 *
 * Orthogonal to {@link AuthPolicy} on purpose: `'biometricOnly'` must never
 * imply invalidation, or a user adding a fingerprint silently destroys their
 * wallet. Opting in is explicit.
 */
export type InvalidationPolicy = 'onEnrollmentChange' | 'never';

export const DEFAULT_AUTH_POLICY: AuthPolicy = 'biometricOrPasscode';
export const DEFAULT_INVALIDATION_POLICY: InvalidationPolicy = 'never';

/** Uncompressed SEC1 public key: `0x04` followed by 64 bytes. */
export type PublicKeyHex = `0x${string}`;

/** 65-byte Ethereum signature: `r || s || v`, with `v` 27 or 28. */
export type SignatureHex = `0x${string}`;

type KeyOptions = {
  policy?: AuthPolicy;
  invalidation?: InvalidationPolicy;
};

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

const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})+$/;
const HEX_32_BYTES = /^(?:0x)?[0-9a-fA-F]{64}$/;

function strip0x(value: string): string {
  return value.startsWith('0x') || value.startsWith('0X')
    ? value.slice(2)
    : value;
}

function prefix0x(value: string): `0x${string}` {
  return (value.startsWith('0x') ? value : `0x${value}`) as `0x${string}`;
}

function assertKeyId(keyId: string): void {
  if (typeof keyId !== 'string' || keyId.trim() === '') {
    throw new KeystoreError('UNKNOWN', 'A non-empty `keyId` is required.');
  }
}

function assertReason(reason: string, action: string): void {
  // iOS raises on an empty localizedReason rather than failing gracefully, so
  // this is checked before the bridge to keep both platforms consistent.
  if (typeof reason !== 'string' || reason.trim() === '') {
    throw new KeystoreError(
      'UNKNOWN',
      `A non-empty \`reason\` is required to ${action}.`
    );
  }
}

/**
 * Which biometric modality the hardware supports, whether or not anything is
 * enrolled. Resolves `'none'` when there is no hardware; never rejects.
 *
 * Enrollment state comes from {@link authenticate} via `NOT_ENROLLED`.
 */
export async function getBiometryType(): Promise<BiometryType> {
  const type = await NativeWalletKeystore.getBiometryType();
  // A native layer newer than this JS could return a modality we don't know.
  return (BIOMETRY_TYPES.has(type) ? type : 'biometric') as BiometryType;
}

/**
 * Prompts for device-owner authentication.
 *
 * A UX gate, not a security boundary — the boolean can be faked by a
 * compromised bundle. Use {@link signDigest} where it actually matters.
 *
 * Never resolves `false`; every failure rejects.
 *
 * @throws {KeystoreError}
 */
export async function authenticate(
  reason: string,
  policy: AuthPolicy = DEFAULT_AUTH_POLICY
): Promise<boolean> {
  try {
    assertReason(reason, 'authenticate');
    return await NativeWalletKeystore.authenticate(reason, policy);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Stores a secret encrypted under a hardware-bound wrapping key.
 *
 * @throws {KeystoreError} `KEY_ALREADY_EXISTS` if `keyId` is taken; overwriting
 *   is always deliberate.
 */
export async function storeSecret(
  keyId: string,
  secretHex: string,
  options: KeyOptions = {}
): Promise<void> {
  try {
    assertKeyId(keyId);

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
 * The prompt is raised by the keystore as a precondition of using the wrapping
 * key, so it cannot be bypassed from JS.
 *
 * @throws {KeystoreError} `KEY_NOT_FOUND`, `KEY_INVALIDATED`, or any auth code.
 */
export async function getSecret(
  keyId: string,
  reason: string
): Promise<string> {
  try {
    assertKeyId(keyId);
    assertReason(reason, 'read a secret');
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

/** Removes the secret and its wrapping key. Idempotent. */
export async function deleteSecret(keyId: string): Promise<void> {
  try {
    assertKeyId(keyId);
    await NativeWalletKeystore.deleteSecret(keyId);
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Generates a secp256k1 keypair in hardware-wrapped storage.
 *
 * Entropy comes from the platform CSPRNG, never from JavaScript, and the
 * private key never crosses the bridge.
 *
 * @returns The uncompressed public key.
 */
export async function generateKey(
  keyId: string,
  options: KeyOptions = {}
): Promise<PublicKeyHex> {
  try {
    assertKeyId(keyId);
    return prefix0x(
      await NativeWalletKeystore.generateKey(
        keyId,
        options.policy ?? DEFAULT_AUTH_POLICY,
        options.invalidation ?? DEFAULT_INVALIDATION_POLICY
      )
    );
  } catch (error) {
    throw toKeystoreError(error);
  }
}

/**
 * Imports an existing secp256k1 private key.
 *
 * @throws {KeystoreError} `INVALID_KEY` unless the key is in [1, n-1]. Keys
 *   outside that range are rejected rather than clamped.
 */
export async function importPrivateKey(
  keyId: string,
  privateKeyHex: string,
  options: KeyOptions = {}
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

    // The range check stays native, where the curve order is already at hand.
    return prefix0x(
      await NativeWalletKeystore.importPrivateKey(
        keyId,
        strip0x(privateKeyHex),
        options.policy ?? DEFAULT_AUTH_POLICY,
        options.invalidation ?? DEFAULT_INVALIDATION_POLICY
      )
    );
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
 * Only a digest crosses the boundary — never a message or a transaction.
 * Keccak and EIP-191/712/155 encoding stay in JS, which keeps this module
 * curve-specific but chain-agnostic.
 *
 * @returns 65 bytes, `r || s || v`, low-s normalized per EIP-2 with `v` of
 *   27/28 — byte-identical to viem.
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

    assertReason(reason, 'sign');

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
 * For user-initiated backup only. The result lands in the JS heap where it
 * cannot be zeroed, so prefer {@link signDigest} for everyday use.
 */
export async function exportPrivateKey(
  keyId: string,
  reason: string
): Promise<string> {
  try {
    assertKeyId(keyId);
    assertReason(reason, 'export a private key');
    return prefix0x(await NativeWalletKeystore.exportPrivateKey(keyId, reason));
  } catch (error) {
    throw toKeystoreError(error);
  }
}
