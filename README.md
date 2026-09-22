# react-native-wallet-keystore

Hardware-protected secret storage for React Native, built on the iOS Secure
Enclave and the Android Keystore.

> **Status: v0.2.** Authentication and hardware-wrapped secret storage.
> Signing (`signDigest`) arrives in v0.3.

## Why a wrapping key

Neither the Secure Enclave nor the Android Keystore supports **secp256k1**, the
curve Ethereum uses. An EVM private key therefore cannot live in hardware — no
amount of API design changes that.

So the key is wrapped instead. A hardware-bound key that the OS *does* support
encrypts it, and only the ciphertext is ever at rest:

| | iOS | Android |
| --- | --- | --- |
| Wrapping key | P-256 in the Secure Enclave | AES-256-GCM in the Keystore (StrongBox where available) |
| Scheme | ECIES (`eciesEncryptionCofactorX963SHA256AESGCM`) | AES-GCM via `BiometricPrompt.CryptoObject` |
| Ciphertext at rest | Keychain generic password | `SharedPreferences` |

The private key exists in plaintext only inside a single native function call,
and the buffer is zeroed afterwards.

## Install

```sh
npm install react-native-wallet-keystore
cd ios && pod install
```

Requires Node >= 22.12 to build. iOS needs `NSFaceIDUsageDescription` in
`Info.plist`; without it the OS terminates the app on the first Face ID call.

## Usage

```ts
import {
  getBiometryType,
  storeSecret,
  getSecret,
  KeystoreError,
} from 'react-native-wallet-keystore';

await storeSecret('wallet-1', privateKeyHex, {
  policy: 'biometricOrPasscode',
  invalidation: 'never',
});

try {
  const hex = await getSecret('wallet-1', 'Unlock your wallet');
} catch (error) {
  if (error instanceof KeystoreError && error.code === 'NOT_ENROLLED') {
    // Send the user to Settings. Retrying will not help.
  }
}
```

## Two independent policies

`AuthPolicy` controls **which authenticators are accepted**.
`InvalidationPolicy` controls **when the key is destroyed**. They are separate
on purpose.

```ts
type AuthPolicy = 'biometricOnly' | 'biometricOrPasscode' | 'none';  // default: biometricOrPasscode
type InvalidationPolicy = 'onEnrollmentChange' | 'never';            // default: never
```

Several libraries collapse these, letting "biometric only" silently imply
`.biometryCurrentSet` / `setInvalidatedByBiometricEnrollment(true)`. The
consequence is severe and non-obvious: **a user who adds a fingerprint destroys
the wrapping key, and the wallet becomes unrecoverable.** Opting into that has
to be deliberate, so `invalidation` defaults to `'never'` and is never inferred.

`biometricOrPasscode` is the default because for a wallet the failure modes are
asymmetric. Biometric-only risks permanent loss of access to funds; the passcode
fallback is a credential the device already depends on.

## Error codes

Every rejection is a `KeystoreError` with a `.code`. The distinctions exist
because each one implies a different action.

| Code | Meaning | What the caller should do |
| --- | --- | --- |
| `NOT_AVAILABLE` | No biometric hardware, or unavailable | Fall back to another factor |
| `NOT_ENROLLED` | Nothing enrolled | Send to Settings — retrying cannot help |
| `USER_CANCELED` | User dismissed the prompt | Safe to re-prompt |
| `USER_FALLBACK` | User chose the fallback affordance | Offer a passcode path |
| `LOCKOUT` | Too many attempts, temporary | Retry after a cooldown |
| `LOCKOUT_PERMANENT` | Locked until device credential is used | Android only — see below |
| `SYSTEM_CANCEL` | The OS dismissed the prompt | Not user intent; retry later |
| `KEY_NOT_FOUND` | No secret under that `keyId` | Store one first |
| `KEY_ALREADY_EXISTS` | `keyId` is taken | Delete first — overwrites are explicit |
| `KEY_INVALIDATED` | **The secret is gone for good** | Start recovery from backup |
| `STORAGE_ERROR` | Keychain/Keystore itself failed | Surface as unexpected |
| `UNKNOWN` | Unrecognized | Inspect `.nativeCode` for the raw value |

An unrecognized native code maps to `UNKNOWN` but preserves the original string
on `.nativeCode`, so a new platform error stays diagnosable.

## Honest limitations

**`authenticate()` is a UX gate, not a security boundary.** It returns a boolean,
and a boolean returned to JavaScript can be faked by a compromised bundle. Use it
to decide what to show, never to decide whether to release a secret.

**`getSecret()` is the real boundary.** The wrapping key is unusable until the OS
validates the user — on Android via a `CryptoObject` that binds the
authentication to the specific cipher operation. There is no boolean in that path
to lie about.

**`getSecret()` returns a string into the JS heap**, where it cannot be reliably
zeroed and survives until garbage collection. This is inherent to crossing the
bridge. It is why `signDigest` will exist in v0.3: so the normal path never
surfaces the key to JS at all. Treat `getSecret` as a user-initiated *export*
path, not the everyday one.

**Platform asymmetries**, stated rather than papered over:

- **iOS has no `LOCKOUT_PERMANENT`.** It resolves permanent biometric lockout
  inside the system prompt by demanding the passcode, so the state never reaches
  the app. Android surfaces it and it is terminal until a device credential is
  used.
- **Android prompts on `storeSecret`; iOS does not.** iOS encrypts with the
  public half of an enclave keypair, which needs no authentication. Android's
  wrapping key is symmetric, and `setUserAuthenticationRequired(true)` governs
  *every* use of it. Making storage silent on Android would mean dropping the
  auth requirement from the key entirely.
- **Android cannot report which biometric is enrolled.** `PackageManager` reports
  hardware presence only, so `getBiometryType()` returns the specific modality
  when exactly one is present and the generic `'biometric'` otherwise. iOS
  reports `faceId` / `touchId` / `opticId` exactly.
- **`biometricOrPasscode` degrades below API 30.** `BIOMETRIC_STRONG or
  DEVICE_CREDENTIAL` is rejected by `setAllowedAuthenticators` before Android 11,
  so API 24–29 falls back to biometric-only rather than silently accepting a
  weaker credential.
- **StrongBox is not guaranteed.** It throws rather than degrading on devices
  without it, so the implementation catches and retries without.

## License

MIT
