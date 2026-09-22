import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Codegen contract. Deliberately narrow: codegen only supports a small set of
 * types, and string-literal unions are handled inconsistently across React
 * Native versions, so everything crossing the bridge is a plain `string`.
 *
 * The typed surface (`BiometryType`, `AuthPolicy`, `InvalidationPolicy`,
 * `KeystoreError`) lives in `src/index.tsx` and narrows these values.
 */
export interface Spec extends TurboModule {
  /**
   * Resolves the biometric modality the *hardware* supports, independent of
   * whether anything is currently enrolled. Never rejects — absence of
   * hardware resolves `'none'`. Use `authenticate` to discover enrollment
   * state, which surfaces `NOT_ENROLLED`.
   */
  getBiometryType(): Promise<string>;

  /**
   * Prompts for device-owner authentication. Resolves `true` on success, or
   * rejects with one of the `KeystoreErrorCode` strings.
   *
   * This is a UX gate, not a security boundary — see the README. The boolean it
   * returns can be faked by a compromised JS bundle; only `getSecret` is
   * cryptographically bound to the authentication.
   */
  authenticate(reason: string, policy: string): Promise<boolean>;

  /**
   * Encrypts `secretHex` under a hardware-bound wrapping key and persists the
   * ciphertext. Encryption needs no authentication; only retrieval prompts.
   *
   * Rejects `KEY_ALREADY_EXISTS` when `keyId` is taken, so that overwriting a
   * wallet key is always a deliberate act.
   */
  storeSecret(
    keyId: string,
    secretHex: string,
    policy: string,
    invalidation: string
  ): Promise<void>;

  /**
   * Authenticates and decrypts. The prompt is raised by the keystore itself as
   * a precondition of using the wrapping key, not by a separate check.
   */
  getSecret(keyId: string, reason: string): Promise<string>;

  hasSecret(keyId: string): Promise<boolean>;

  /** Idempotent: deleting an absent `keyId` resolves rather than rejecting. */
  deleteSecret(keyId: string): Promise<void>;

  /**
   * Generates a secp256k1 keypair and stores the private key under the same
   * hardware-wrapping path as `storeSecret`. Resolves the uncompressed public
   * key as hex.
   *
   * Entropy comes from the platform CSPRNG, never from JS, and the private key
   * never crosses the bridge during generation.
   */
  generateKey(
    keyId: string,
    policy: string,
    invalidation: string
  ): Promise<string>;

  /** Imports an existing key. Rejects `INVALID_KEY` unless it is in [1, n-1]. */
  importPrivateKey(
    keyId: string,
    privateKeyHex: string,
    policy: string,
    invalidation: string
  ): Promise<string>;

  /**
   * The uncompressed public key. Deliberately requires no authentication —
   * it is not secret, and prompting to see your own address is hostile.
   */
  getPublicKey(keyId: string): Promise<string>;

  /**
   * Signs a 32-byte digest, returning 65 bytes as `r || s || v` hex.
   *
   * `s` is low-s normalized per EIP-2 and `v` is 27/28, so the result is
   * byte-identical to what viem produces for the same key and digest.
   */
  signDigest(keyId: string, digestHex: string, reason: string): Promise<string>;

  /** Backup/export path. Authenticates, then surfaces the key to JS. */
  exportPrivateKey(keyId: string, reason: string): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('WalletKeystore');
