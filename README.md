# react-native-wallet-keystore

[![npm](https://img.shields.io/npm/v/react-native-wallet-keystore.svg)](https://www.npmjs.com/package/react-native-wallet-keystore)
[![CI](https://github.com/miroosama/react-native-wallet-keystore/actions/workflows/ci.yml/badge.svg)](https://github.com/miroosama/react-native-wallet-keystore/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/react-native-wallet-keystore.svg)](./LICENSE)

Hardware-protected wallet keys for React Native. Store a secp256k1 private key
encrypted by a hardware-bound key, sign with it behind Face ID or fingerprint,
and plug it straight into viem.

```ts
import { createWalletClient, http, parseEther } from 'viem';
import { base } from 'viem/chains';
import { generateKey, hasSecret } from 'react-native-wallet-keystore';
import { toKeystoreAccount } from 'react-native-wallet-keystore/viem';

// Once, during onboarding. The private key never reaches JavaScript.
if (!(await hasSecret('my-wallet'))) {
  await generateKey('my-wallet');
}

const account = await toKeystoreAccount('my-wallet');
const client = createWalletClient({ account, chain: base, transport: http() });

// Prompts for Face ID / fingerprint before signing.
await client.sendTransaction({ to: '0x…', value: parseEther('0.01') });
```

> **Status: 0.1.0, unaudited.** The cryptographic output is verified
> byte-identical to viem across both platforms, and the full API is tested on
> physical hardware. It has not had a third-party security review. Treat it
> accordingly for funds you can't afford to lose, and read
> [Known limitations](#known-limitations) before shipping.

## Why this exists

The iOS Secure Enclave and Android Keystore only support P-256. Ethereum uses
secp256k1. That means the existing hardware-backed signing libraries — good
libraries, solving a real problem — **cannot sign an Ethereum transaction**,
because the key they protect can't be the right kind of key.

This library takes the other approach. The wallet key is generated in software
and encrypted at rest by a key that *does* live in hardware — a P-256 key in the
Secure Enclave on iOS, an AES-256-GCM Keystore key on Android. Decryption
requires user authentication, signing happens in native memory, and the
plaintext key never crosses into JavaScript.

If you need P-256 device signing — passkeys, device binding, request
attestation — use a library built for that instead. This one is for wallet keys.

## Install

```sh
npm install react-native-wallet-keystore
cd ios && pod install
```

`viem` is an optional peer dependency, needed only for the
`react-native-wallet-keystore/viem` adapter:

```sh
npm install viem
```

Building requires **Node >= 22.12** (the version where `require(esm)` works
unflagged). This is enforced via `engines`.

> **Expo:** this module contains native code, so it cannot run in Expo Go. Use a
> development build — `npx expo prebuild` then `npx expo run:ios`.

## Platform setup

### iOS

Add `NSFaceIDUsageDescription` to `Info.plist`. Without it, iOS terminates the
app the first time Face ID is requested.

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to unlock your wallet key.</string>
```

Minimum deployment target follows React Native's. No other configuration — the
podspec links `LocalAuthentication`, `Security`, and `secp256k1.swift` itself.

### Android

`minSdkVersion` 24. The library declares its own dependencies
(`androidx.biometric`, `org.bouncycastle:bcprov-jdk18on`), so no manifest or
Gradle changes are required.

Your `MainActivity` must extend `FragmentActivity` — React Native's
`ReactActivity` already does, so this only matters if you have replaced it.

## API

All functions reject with a [`KeystoreError`](#error-codes); none resolve a
failure value.

**Keys and secrets share one namespace.** A wallet key *is* a stored secret —
`generateKey` wraps a secp256k1 key through the same path `storeSecret` uses for
arbitrary bytes. So `hasSecret`, `deleteSecret` and `getSecret` all operate on
keys too, and a `keyId` used by `generateKey` collides with one used by
`storeSecret`. This is why the quickstart checks `hasSecret('my-wallet')` before
calling `generateKey` — it reads like a mismatch and isn't.

### Keys

`generateKey` and `importPrivateKey` are alternatives, not steps — new wallet
versus restoring one the user already has.

> **`importPrivateKey` takes a raw 32-byte key, not a seed phrase.** Deriving
> one from twelve words is BIP-39/BIP-32 and stays in your app (viem's
> `mnemonicToAccount` does it). Note that derivation happens in JavaScript, so
> an imported key is briefly in the JS heap before it is wrapped —
> `generateKey` is the only path where the key never leaves native memory.

#### `generateKey(keyId, options?): Promise<PublicKeyHex>`

Generates a secp256k1 keypair in hardware-wrapped storage and returns the
uncompressed public key. Entropy comes from the platform CSPRNG; the private key
never crosses the bridge.

```ts
const publicKey = await generateKey('my-wallet', {
  policy: 'biometricOrPasscode', // default
  invalidation: 'never', // default
});
```

> ⚠️ **`invalidation: 'onEnrollmentChange'` can destroy funds.** It is stronger
> against coercion, and it will **permanently destroy the key** if the user adds
> a fingerprint or re-enrolls Face ID. The encrypted secret becomes
> unrecoverable and `getSecret`/`signDigest` reject with `KEY_INVALIDATED`. Do
> not ship it without mandatory backup during onboarding.

#### `importPrivateKey(keyId, privateKeyHex, options?): Promise<PublicKeyHex>`

Imports an existing 32-byte key — the restore-from-backup path. Rejects
`INVALID_KEY` unless the key is in `[1, n-1]`; out-of-range keys are rejected,
never clamped.

#### `getPublicKey(keyId): Promise<PublicKeyHex>`

The uncompressed public key. **Does not authenticate** — a public key is not
secret, and prompting to see your own address is hostile.

#### `exportPrivateKey(keyId, reason): Promise<string>`

Authenticates, then returns the raw private key. For user-initiated backup only;
see [Known limitations](#known-limitations).

### Signing

#### `signDigest(keyId, digestHex, reason): Promise<SignatureHex>`

Authenticates, then signs a **32-byte digest**. Returns 65 bytes as
`r || s || v`, low-s normalized per EIP-2 with `v` of 27/28 — byte-identical to
viem for the same key and digest.

Only a digest crosses the boundary, never a message or a transaction. Keccak and
all EIP-191/712/155 encoding stay in JavaScript, which keeps this module
curve-specific but chain-agnostic.

```ts
import { keccak256, toHex } from 'viem';

const signature = await signDigest(
  'my-wallet',
  keccak256(toHex('hello')),
  'Sign this message'
);
```

#### `toKeystoreAccount(keyId, options?): Promise<LocalAccount>`

From `react-native-wallet-keystore/viem`. Returns a viem `LocalAccount` that
works anywhere viem accepts one — `signMessage`, `signTypedData`,
`signTransaction` and `sendTransaction` all route through `signDigest`.

```ts
const account = await toKeystoreAccount('my-wallet', {
  reason: 'Approve this swap', // shown in the prompt
  publicKey, // optional, skips a native round-trip
});
```

Each signature raises its own prompt, so batching several will prompt several
times.

### Secrets

The same wrapping path works for any bytes — mnemonics, API keys, session
tokens.

| | |
| --- | --- |
| `storeSecret(keyId, secretHex, options?)` | Rejects `KEY_ALREADY_EXISTS` if taken |
| `getSecret(keyId, reason)` | Authenticates, returns hex |
| `hasSecret(keyId)` | Presence check, no prompt |
| `deleteSecret(keyId)` | Removes secret and wrapping key; idempotent |

### Authentication

#### `getBiometryType(): Promise<BiometryType>`

Which modality the *hardware* supports, whether or not anything is enrolled — so
you can write "Enable Face ID in Settings" rather than a generic message.
Resolves `'none'` when there is no hardware; never rejects.

#### `authenticate(reason, policy?): Promise<boolean>`

Prompts for device-owner authentication. See
[the security model](#whats-protected-and-what-isnt) before using this to gate
anything.

### Policies

```ts
type AuthPolicy = 'biometricOnly' | 'biometricOrPasscode';
type InvalidationPolicy = 'onEnrollmentChange' | 'never';
```

These are deliberately **orthogonal**. Which authenticators are accepted is a
separate question from when the key is destroyed. Several libraries bind them,
so that "biometric only" silently implies invalidation — and a user adding a
fingerprint destroys their wallet. Here, opting into that is explicit.

`biometricOrPasscode` is the default because for a wallet the failure modes are
asymmetric: biometric-only risks permanent loss of access to funds, while the
passcode fallback is a credential the device already depends on.

The policy is fixed at key creation. Changing it later means
`deleteSecret` and re-creating.

## Error codes

Every rejection is a `KeystoreError` with a `.code`. The distinctions are
load-bearing — each implies a different action.

```ts
import { KeystoreError } from 'react-native-wallet-keystore';

try {
  await signDigest('my-wallet', digest, 'Sign');
} catch (error) {
  if (error instanceof KeystoreError && error.code === 'NOT_ENROLLED') {
    // Send the user to Settings. Retrying will not help.
  }
}
```

| Code | Meaning | What to do |
| --- | --- | --- |
| `NOT_AVAILABLE` | No biometric hardware, or unavailable | Fall back to another factor |
| `NOT_ENROLLED` | Nothing enrolled | Send to Settings — retrying cannot help |
| `USER_CANCELED` | User dismissed the prompt | Safe to re-prompt |
| `USER_FALLBACK` | User chose the fallback affordance | Offer a passcode path |
| `LOCKOUT` | Too many attempts, temporary | Retry after a cooldown |
| `LOCKOUT_PERMANENT` | Locked until device credential is used | Android only; prompt for PIN/pattern |
| `SYSTEM_CANCEL` | OS dismissed the prompt | Not user intent; retry later |
| `KEY_NOT_FOUND` | No secret under that `keyId` | Generate or import one |
| `KEY_ALREADY_EXISTS` | `keyId` is taken | `deleteSecret` first — overwrites are explicit |
| `KEY_INVALIDATED` | **The secret is gone for good** | Start recovery from backup |
| `INVALID_KEY` | Key outside `[1, n-1]`, or digest not 32 bytes | Fix the input |
| `STORAGE_ERROR` | Keychain/Keystore itself failed | Surface as unexpected |
| `UNKNOWN` | Unrecognized | Inspect `.nativeCode` for the raw value |

An unrecognized native code maps to `UNKNOWN` but preserves the original string
on `.nativeCode`, so a new platform error stays diagnosable.

## What's protected, and what isn't

**`authenticate()` is a UX gate, not a security boundary.** It returns a
boolean, and a compromised JavaScript bundle can pretend that boolean was
`true`. Use it to decide when to show a prompt, never to decide whether to
release a secret.

**`signDigest()` and `getSecret()` are the real boundary.** The key is unusable
until the OS validates authentication against hardware. On Android this is
enforced by a `BiometricPrompt.CryptoObject`: the `Cipher` is inoperable until
the OS authorizes it, so there is no code path that decrypts without a
successful prompt. Every stored key requires authentication — there is no
opt-out.

**The key is not inside the enclave.** It's encrypted by a key that is. A
sufficiently compromised device that can drive the biometric prompt can obtain
the plaintext. The protection is against key extraction at rest, not against an
attacker in control of an unlocked device.

**Normal signing never exposes the key to JavaScript.** `signDigest` takes a
32-byte digest and returns a signature; the private key stays in native memory.
`exportPrivateKey` exists for user-initiated backup and does return the key to
JS, where it lands in the heap and can't be reliably cleared. That's inherent,
which is why export is the exception and not the path.

## Known limitations

**Zeroing is best-effort.** Key buffers are overwritten immediately after use —
on iOS through a volatile pointer, because a plain `memset` over memory that is
never read again is legal for the compiler to eliminate entirely, so the naive
version looks right in review and does nothing at `-O3`. On Android buffers are
cleared with `ByteArray.fill(0)`, which the JVM offers no stronger guarantee
than. Either way this shrinks the window rather than closing it; managed
runtimes copy memory in ways you don't control.

**The iOS secp256k1 dependency is unmaintained.** `secp256k1.swift` vendors
genuine bitcoin-core source with the recovery module enabled, and its output is
verified byte-identical to viem, so this is a staleness risk rather than a
correctness one — later upstream hardening does not flow in. React Native 0.86
ships an `spm_dependency` helper that makes moving to the maintained package
practical; it needs a Swift bridging layer, since the current implementation
calls libsecp256k1's C API directly.

**Platform asymmetries, all real:**

- iOS has no `LOCKOUT_PERMANENT` — it resolves permanent lockout inside the
  system prompt by requiring the device passcode, so the state never reaches the
  app
- Android prompts on `storeSecret` as well as `getSecret`, because
  `setUserAuthenticationRequired` governs every use of a symmetric key. iOS
  encrypts with the public half of an enclave keypair and needs no
  authentication to store
- Android can't report *which* biometric is enrolled — `PackageManager` reports
  hardware presence only — so `getBiometryType` returns `'biometric'` when more
  than one modality is present
- `biometricOrPasscode` degrades to biometric-only below API 30, where
  `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` is rejected by
  `setAllowedAuthenticators`

**`KEY_INVALIDATED` is verified on Android, not iOS.** The logic is shared and
identical, but reproducing it on iOS means resetting Face ID on a device in
daily use.

## When not to use this

If you're building on smart-contract accounts, passkeys plus the secp256r1
precompile (RIP-7212, live on Base and other L2s) may be a better fit — there is
no private key to protect at all. This library is for applications that need a
real EOA key the user owns and can export.

## Contributing

Requires Node >= 22.12; the repo pins an exact version in `.nvmrc`.

```sh
nvm use
yarn
yarn example ios      # or: yarn example android
```

The example app exercises every API call, grouped in the order you'd use them.
It is the fastest way to see a change working on a device.

```sh
yarn test        # jest, including known-answer vectors against viem
yarn typecheck
yarn lint
```

The known-answer vectors in `src/__fixtures__` pin native output byte-for-byte
against viem. They are what catch low-s errors, recovery-id errors, and
divergence between libsecp256k1 on iOS and BouncyCastle on Android. Regenerate
them with `node src/__fixtures__/generate.mjs`.

Note that the example app resolves the library from `src/` via a custom export
condition, so it cannot catch packaging mistakes. Validate those by packing the
tarball and installing it into a fresh app:

```sh
npm pack
```

## License

MIT
