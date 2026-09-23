import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Codegen contract.
 *
 * Everything crossing the bridge is a plain `string` on purpose: codegen
 * supports a narrow set of types, and string-literal unions are handled
 * inconsistently across React Native versions. The typed surface lives in
 * `keystore.ts`, which narrows these values.
 */
export interface Spec extends TurboModule {
  getBiometryType(): Promise<string>;
  authenticate(reason: string, policy: string): Promise<boolean>;

  storeSecret(
    keyId: string,
    secretHex: string,
    policy: string,
    invalidation: string
  ): Promise<void>;
  getSecret(keyId: string, reason: string): Promise<string>;
  hasSecret(keyId: string): Promise<boolean>;
  deleteSecret(keyId: string): Promise<void>;

  generateKey(
    keyId: string,
    policy: string,
    invalidation: string
  ): Promise<string>;
  importPrivateKey(
    keyId: string,
    privateKeyHex: string,
    policy: string,
    invalidation: string
  ): Promise<string>;
  getPublicKey(keyId: string): Promise<string>;

  /** Returns 65 bytes of hex: `r || s || v`, low-s normalized, `v` of 27/28. */
  signDigest(keyId: string, digestHex: string, reason: string): Promise<string>;
  exportPrivateKey(keyId: string, reason: string): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('WalletKeystore');
