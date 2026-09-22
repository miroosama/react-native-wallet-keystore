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
}

export default TurboModuleRegistry.getEnforcing<Spec>('WalletKeystore');
