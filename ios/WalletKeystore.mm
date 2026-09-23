#import "WalletKeystore.h"

#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#import <secp256k1.h>
#import <secp256k1_recovery.h>

static NSString *const WKPolicyBiometricOnly = @"biometricOnly";
static NSString *const WKPolicyNone = @"none";
static NSString *const WKInvalidationOnEnrollmentChange = @"onEnrollmentChange";

static NSString *const WKCodeNotAvailable = @"NOT_AVAILABLE";
static NSString *const WKCodeNotEnrolled = @"NOT_ENROLLED";
static NSString *const WKCodeUserCanceled = @"USER_CANCELED";
static NSString *const WKCodeUserFallback = @"USER_FALLBACK";
static NSString *const WKCodeLockout = @"LOCKOUT";
static NSString *const WKCodeSystemCancel = @"SYSTEM_CANCEL";
static NSString *const WKCodeKeyNotFound = @"KEY_NOT_FOUND";
static NSString *const WKCodeKeyAlreadyExists = @"KEY_ALREADY_EXISTS";
static NSString *const WKCodeKeyInvalidated = @"KEY_INVALIDATED";
static NSString *const WKCodeStorageError = @"STORAGE_ERROR";
static NSString *const WKCodeUnknown = @"UNKNOWN";

static NSString *const WKCodeInvalidKey = @"INVALID_KEY";

static NSString *const WKKeychainService = @"com.walletkeystore.secret";
static NSString *const WKPublicKeyService = @"com.walletkeystore.publickey";
static NSString *const WKKeyTagPrefix = @"com.walletkeystore.wrap.";

/**
 * Zeroes a buffer through a volatile pointer. A plain memset over memory that is
 * never read again is dead-store-eliminated at -O3, leaving the key in place.
 */
static void WKSecureZero(void *buffer, size_t length)
{
  if (buffer == NULL || length == 0) {
    return;
  }
  volatile unsigned char *p = (volatile unsigned char *)buffer;
  while (length--) {
    *p++ = 0;
  }
}

/**
 * Shared libsecp256k1 context — expensive to build, safe to share once
 * randomized. Randomizing blinds against side-channel key recovery.
 */
static secp256k1_context *WKSecpContext(void)
{
  static secp256k1_context *context = NULL;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t seed[32];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(seed), seed) == errSecSuccess) {
      // Hardening only; the context still works if this fails.
      (void)secp256k1_context_randomize(context, seed);
    }
    WKSecureZero(seed, sizeof(seed));
  });
  return context;
}

@implementation WalletKeystore

#pragma mark - Error mapping

/**
 * Maps an LAError onto the cross-platform code set. No LOCKOUT_PERMANENT case:
 * iOS resolves permanent lockout inside the prompt by demanding the passcode,
 * so it never reaches the app.
 */
static NSString *WKCodeFromLAError(NSError *_Nullable error)
{
  if (error == nil) {
    return WKCodeUnknown;
  }

  switch (error.code) {
    case LAErrorBiometryNotAvailable:
      return WKCodeNotAvailable;

    // No passcode set means device-owner auth cannot succeed at all, which is
    // an enrollment problem from the caller's point of view, not a fault.
    case LAErrorBiometryNotEnrolled:
    case LAErrorPasscodeNotSet:
      return WKCodeNotEnrolled;

    // appCancel is the app being backgrounded mid-prompt. Grouped with an
    // explicit tap on Cancel because both mean "no answer, safe to re-prompt".
    case LAErrorUserCancel:
    case LAErrorAppCancel:
      return WKCodeUserCanceled;

    case LAErrorUserFallback:
      return WKCodeUserFallback;

    case LAErrorBiometryLockout:
      return WKCodeLockout;

    // systemCancel is the OS tearing down the prompt; notInteractive means no
    // UI could be presented. Neither is user intent, so neither is a cancel.
    case LAErrorSystemCancel:
    case LAErrorNotInteractive:
      return WKCodeSystemCancel;

    default:
      return WKCodeUnknown;
  }
}

/** Maps a Keychain/SecKey OSStatus onto the cross-platform code set. */
static NSString *WKCodeFromOSStatus(OSStatus status)
{
  switch (status) {
    case errSecItemNotFound:
      return WKCodeKeyNotFound;

    case errSecDuplicateItem:
      return WKCodeKeyAlreadyExists;

    case errSecUserCanceled:
      return WKCodeUserCanceled;

    // No enrolled credential can satisfy the access control. Against a
    // .biometryCurrentSet key this is permanent, not a retryable failure.
    case errSecAuthFailed:
      return WKCodeKeyInvalidated;

    case errSecInteractionNotAllowed:
      return WKCodeSystemCancel;

    default:
      return WKCodeStorageError;
  }
}

/**
 * A SecKey CFError may carry an LAError or an OSStatus depending on whether
 * auth or the keychain failed. Unwrap both, or a cancel reads as a storage bug.
 */
static NSString *WKCodeFromSecError(NSError *_Nullable error)
{
  if (error == nil) {
    return WKCodeUnknown;
  }

  if ([error.domain isEqualToString:LAErrorDomain]) {
    return WKCodeFromLAError(error);
  }

  if ([error.domain isEqualToString:NSOSStatusErrorDomain]) {
    return WKCodeFromOSStatus((OSStatus)error.code);
  }

  // The underlying error is where LocalAuthentication surfaces when the
  // failure happened inside a SecKey operation rather than an LAContext.
  NSError *underlying = error.userInfo[NSUnderlyingErrorKey];
  if (underlying != nil && [underlying.domain isEqualToString:LAErrorDomain]) {
    return WKCodeFromLAError(underlying);
  }

  return WKCodeUnknown;
}

#pragma mark - Hex

static NSData *_Nullable WKDataFromHex(NSString *hex)
{
  if (hex.length % 2 != 0) {
    return nil;
  }

  NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
  for (NSUInteger i = 0; i < hex.length; i += 2) {
    unsigned int byte = 0;
    NSString *pair = [hex substringWithRange:NSMakeRange(i, 2)];
    if (![[NSScanner scannerWithString:pair] scanHexInt:&byte]) {
      return nil;
    }
    uint8_t value = (uint8_t)byte;
    [data appendBytes:&value length:1];
  }
  return data;
}

static NSString *WKHexFromData(NSData *data)
{
  const uint8_t *bytes = (const uint8_t *)data.bytes;
  NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
  for (NSUInteger i = 0; i < data.length; i++) {
    [hex appendFormat:@"%02x", bytes[i]];
  }
  return hex;
}

#pragma mark - Key and item helpers

/**
 * Picks an ECIES variant the key accepts, preferring the variable-IV form that
 * Secure Enclave documents. Driven by the private key: the public half accepts
 * more, so choosing on it could store data that never decrypts.
 */
static SecKeyAlgorithm _Nullable WKECIESAlgorithm(SecKeyRef privateKey)
{
  SecKeyAlgorithm candidates[] = {
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
  };

  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    if (SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt,
                                   candidates[i])) {
      return candidates[i];
    }
  }
  return NULL;
}

static NSData *WKKeyTag(NSString *keyId)
{
  return [[WKKeyTagPrefix stringByAppendingString:keyId]
      dataUsingEncoding:NSUTF8StringEncoding];
}

/**
 * Translates the two orthogonal policies into Secure Enclave access control.
 *
 * The invalidation axis is kept separate from the authenticator axis on
 * purpose. .biometryCurrentSet destroys the key on any enrollment change, so
 * letting 'biometricOnly' imply it would mean a user adding a fingerprint
 * silently loses their wallet. It is opt-in via `invalidation` alone.
 */
static SecAccessControlCreateFlags WKAccessControlFlags(NSString *policy,
                                                        NSString *invalidation)
{
  BOOL biometricOnly = [policy isEqualToString:WKPolicyBiometricOnly];
  BOOL invalidates = [invalidation isEqualToString:WKInvalidationOnEnrollmentChange];

  // Required for any Secure Enclave key that will perform private-key
  // operations. Omitting it still creates the key and still allows public-key
  // encryption, so the mistake only surfaces later, as "Operation is not
  // allowed" on the first decrypt.
  SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;

  if (biometricOnly) {
    return flags | (invalidates ? kSecAccessControlBiometryCurrentSet
                                : kSecAccessControlBiometryAny);
  }

  if (invalidates) {
    // Biometrics pinned to the current enrollment, but the passcode remains a
    // route in — otherwise this would be indistinguishable from biometricOnly.
    return flags | kSecAccessControlBiometryCurrentSet | kSecAccessControlOr |
           kSecAccessControlDevicePasscode;
  }

  return flags | kSecAccessControlUserPresence;
}

static SecKeyRef _Nullable WKCopyPrivateKey(NSString *keyId,
                                            LAContext *_Nullable context,
                                            OSStatus *outStatus)
{
  NSMutableDictionary *query = [@{
    (__bridge id)kSecClass : (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrApplicationTag : WKKeyTag(keyId),
    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecReturnRef : @YES,
  } mutableCopy];

  if (context != nil) {
    // Carries the prompt's reason, and is what makes the decryption below
    // raise the system prompt rather than failing with interactionNotAllowed.
    query[(__bridge id)kSecUseAuthenticationContext] = context;
  }

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (outStatus != NULL) {
    *outStatus = status;
  }

  return status == errSecSuccess ? (SecKeyRef)result : NULL;
}

static NSDictionary *WKCiphertextQuery(NSString *keyId)
{
  return @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : WKKeychainService,
    (__bridge id)kSecAttrAccount : keyId,
  };
}

static NSDictionary *WKPublicKeyQuery(NSString *keyId)
{
  return @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : WKPublicKeyService,
    (__bridge id)kSecAttrAccount : keyId,
  };
}

#pragma mark - v0.1 authentication

- (void)getBiometryType:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject
{
  LAContext *context = [LAContext new];

  // `biometryType` is unset until a policy has been evaluated, so this call is
  // required even though the result is ignored: we want the hardware modality
  // regardless of enrollment, and canEvaluatePolicy populates it either way.
  NSError *error = nil;
  [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                       error:&error];

  if (@available(iOS 17.0, *)) {
    if (context.biometryType == LABiometryTypeOpticID) {
      resolve(@"opticId");
      return;
    }
  }

  switch (context.biometryType) {
    case LABiometryTypeFaceID:
      resolve(@"faceId");
      return;
    case LABiometryTypeTouchID:
      resolve(@"touchId");
      return;
    default:
      resolve(@"none");
      return;
  }
}

- (void)authenticate:(NSString *)reason
              policy:(NSString *)policy
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  if ([policy isEqualToString:WKPolicyNone]) {
    resolve(@YES);
    return;
  }

  // evaluatePolicy raises NSInvalidArgumentException on an empty reason rather
  // than failing gracefully, so it is rejected before we get there.
  if (reason.length == 0) {
    reject(WKCodeUnknown, @"A non-empty `reason` is required to authenticate.", nil);
    return;
  }

  LAPolicy laPolicy = [policy isEqualToString:WKPolicyBiometricOnly]
      ? LAPolicyDeviceOwnerAuthenticationWithBiometrics
      : LAPolicyDeviceOwnerAuthentication;

  // Fresh context per call: a reused LAContext can satisfy a later evaluation
  // from a cached success, which would mean signing without authenticating.
  LAContext *context = [LAContext new];
  context.touchIDAuthenticationAllowableReuseDuration = 0;

  NSError *availabilityError = nil;
  if (![context canEvaluatePolicy:laPolicy error:&availabilityError]) {
    // This is the only place NOT_AVAILABLE and NOT_ENROLLED can be told apart.
    NSString *code = availabilityError ? WKCodeFromLAError(availabilityError)
                                       : WKCodeNotAvailable;
    NSString *message = availabilityError.localizedDescription
        ?: @"Authentication is not available on this device.";
    reject(code, message, availabilityError);
    return;
  }

  [context evaluatePolicy:laPolicy
          localizedReason:reason
                    reply:^(BOOL success, NSError *_Nullable evaluateError) {
                      // This block runs on a private LocalAuthentication queue.
                      // The promise blocks are thread-safe, so settle directly
                      // rather than hopping to the main queue and stalling it
                      // behind the prompt.
                      if (success) {
                        resolve(@YES);
                        return;
                      }

                      NSString *message = evaluateError.localizedDescription
                          ?: @"Authentication failed.";
                      reject(WKCodeFromLAError(evaluateError), message, evaluateError);
                    }];
}

#pragma mark - v0.2 secret storage

- (void)storeSecret:(NSString *)keyId
          secretHex:(NSString *)secretHex
             policy:(NSString *)policy
       invalidation:(NSString *)invalidation
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [self storeSecretInternal:keyId
                  secretHex:secretHex
                     policy:policy
               invalidation:invalidation
                  onSuccess:^{ resolve(nil); }
                    onError:^(NSString *code, NSString *message) {
                      reject(code, message, nil);
                    }];
}

/**
 * Reused by generateKey and importPrivateKey, which need the outcome rather
 * than a settled promise. Reporting through blocks keeps one copy of the
 * wrapping logic instead of two that can drift.
 */
- (void)storeSecretInternal:(NSString *)keyId
                  secretHex:(NSString *)secretHex
                     policy:(NSString *)policy
               invalidation:(NSString *)invalidation
                  onSuccess:(void (^)(void))onSuccess
                    onError:(void (^)(NSString *code, NSString *message))onError
{
  NSData *secret = WKDataFromHex(secretHex);
  if (secret == nil || secret.length == 0) {
    onError(WKCodeUnknown, @"`secretHex` must be a non-empty hex string.");
    return;
  }

  // Overwriting a wallet key has to be deliberate, so an existing id is an
  // error rather than a silent replace.
  OSStatus existing = errSecSuccess;
  SecKeyRef existingKey = WKCopyPrivateKey(keyId, nil, &existing);
  if (existingKey != NULL) {
    CFRelease(existingKey);
    onError(WKCodeKeyAlreadyExists, @"A secret is already stored under this keyId.");
    return;
  }

  CFErrorRef acError = NULL;
  SecAccessControlRef access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      WKAccessControlFlags(policy, invalidation),
      &acError);

  if (access == NULL) {
    NSError *error = CFBridgingRelease(acError);
    onError(WKCodeFromSecError(error),
            error.localizedDescription ?: @"Could not build access control.");
    return;
  }

  NSDictionary *attributes = @{
    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecAttrKeySizeInBits : @256,
    (__bridge id)kSecAttrTokenID : (__bridge id)kSecAttrTokenIDSecureEnclave,
    (__bridge id)kSecPrivateKeyAttrs : @{
      (__bridge id)kSecAttrIsPermanent : @YES,
      (__bridge id)kSecAttrApplicationTag : WKKeyTag(keyId),
      (__bridge id)kSecAttrAccessControl : (__bridge id)access,
    },
  };

  CFErrorRef keyError = NULL;
  SecKeyRef privateKey =
      SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &keyError);
  CFRelease(access);

  if (privateKey == NULL) {
    NSError *error = CFBridgingRelease(keyError);
    onError(WKCodeFromSecError(error),
            error.localizedDescription ?: @"Could not create the wrapping key.");
    return;
  }

  SecKeyAlgorithm algorithm = WKECIESAlgorithm(privateKey);
  SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
  CFRelease(privateKey);

  if (publicKey == NULL || algorithm == NULL) {
    if (publicKey != NULL) CFRelease(publicKey);
    [self deleteKeyMaterial:keyId];
    onError(WKCodeStorageError,
            algorithm == NULL
                ? @"This device's key does not support any known ECIES variant."
                : @"Could not derive the wrapping public key.");
    return;
  }

  // Encryption uses only the public half, so it needs no authentication. Only
  // reading the secret back prompts the user.
  CFErrorRef encryptError = NULL;
  NSData *ciphertext = CFBridgingRelease(SecKeyCreateEncryptedData(
      publicKey,
      algorithm,
      (__bridge CFDataRef)secret,
      &encryptError));
  CFRelease(publicKey);

  if (ciphertext == nil) {
    NSError *error = CFBridgingRelease(encryptError);
    [self deleteKeyMaterial:keyId];
    onError(WKCodeFromSecError(error),
            error.localizedDescription ?: @"Could not encrypt the secret.");
    return;
  }

  NSMutableDictionary *item = [WKCiphertextQuery(keyId) mutableCopy];
  item[(__bridge id)kSecValueData] = ciphertext;
  // The enclave key is the gate; this item needs no access control of its own,
  // and adding one would prompt twice.
  item[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;

  SecItemDelete((__bridge CFDictionaryRef)WKCiphertextQuery(keyId));
  OSStatus addStatus = SecItemAdd((__bridge CFDictionaryRef)item, NULL);

  if (addStatus != errSecSuccess) {
    // Leaving an enclave key behind with no ciphertext would make the id look
    // taken forever, so roll it back.
    [self deleteKeyMaterial:keyId];
    onError(WKCodeFromOSStatus(addStatus),
            [NSString stringWithFormat:@"Could not store the ciphertext (%d).",
                                       (int)addStatus]);
    return;
  }

  onSuccess();
}

- (void)getSecret:(NSString *)keyId
           reason:(NSString *)reason
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [self getSecretInternal:keyId
                   reason:reason
                onSuccess:^(NSData *plaintext) {
                  NSString *hex = WKHexFromData(plaintext);
                  resolve(hex);
                }
                  onError:^(NSString *code, NSString *message) {
                    reject(code, message, nil);
                  }];
}

/**
 * Hands back raw bytes rather than hex so signDigest never materializes the
 * key as an NSString, which is immutable and cannot be wiped. The buffer is
 * zeroed once the caller's block returns.
 */
- (void)getSecretInternal:(NSString *)keyId
                   reason:(NSString *)reason
                onSuccess:(void (^)(NSData *plaintext))onSuccess
                  onError:(void (^)(NSString *code, NSString *message))onError
{
  NSMutableDictionary *query = [WKCiphertextQuery(keyId) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;

  CFTypeRef stored = NULL;
  OSStatus readStatus =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, &stored);

  if (readStatus != errSecSuccess) {
    onError(WKCodeFromOSStatus(readStatus),
            readStatus == errSecItemNotFound
                ? @"No secret is stored under this keyId."
                : @"Could not read the stored ciphertext.");
    return;
  }

  NSData *ciphertext = CFBridgingRelease(stored);

  LAContext *context = [LAContext new];
  context.touchIDAuthenticationAllowableReuseDuration = 0;
  context.localizedReason = reason;

  // Decryption runs off the main thread: SecKeyCreateDecryptedData blocks
  // until the user answers the prompt, which would deadlock the UI thread.
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    OSStatus keyStatus = errSecSuccess;
    SecKeyRef privateKey = WKCopyPrivateKey(keyId, context, &keyStatus);

    if (privateKey == NULL) {
      // Reaching here means the ciphertext was found but its enclave key was
      // not, so the secret is unrecoverable rather than absent. KEY_NOT_FOUND
      // would send the user to store a new key instead of starting recovery.
      onError(keyStatus == errSecItemNotFound ? WKCodeKeyInvalidated
                                              : WKCodeFromOSStatus(keyStatus),
              keyStatus == errSecItemNotFound
                  ? @"The wrapping key no longer exists; this secret cannot be "
                     "recovered."
                  : @"Could not load the wrapping key.");
      return;
    }

    SecKeyAlgorithm algorithm = WKECIESAlgorithm(privateKey);
    if (algorithm == NULL) {
      CFRelease(privateKey);
      onError(WKCodeStorageError,
              @"The wrapping key does not support any known ECIES variant.");
      return;
    }

    CFErrorRef decryptError = NULL;
    NSData *plaintext = CFBridgingRelease(SecKeyCreateDecryptedData(
        privateKey,
        algorithm,
        (__bridge CFDataRef)ciphertext,
        &decryptError));
    CFRelease(privateKey);

    if (plaintext == nil) {
      NSError *error = CFBridgingRelease(decryptError);
      onError(WKCodeFromSecError(error),
              [NSString stringWithFormat:@"%@ (%@ %ld)",
                                         error.localizedDescription
                                             ?: @"Could not decrypt the secret.",
                                         error.domain ?: @"?", (long)error.code]);
      return;
    }

    onSuccess(plaintext);

    // Best effort only, and only over the buffer we own. Anything the callback
    // derived — an NSString, or the JS string it becomes — cannot be wiped.
    WKSecureZero((void *)plaintext.bytes, plaintext.length);
  });
}

- (void)hasSecret:(NSString *)keyId
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  // Deliberately checks only for the ciphertext item, which needs no
  // authentication — probing the enclave key would prompt the user.
  NSMutableDictionary *query = [WKCiphertextQuery(keyId) mutableCopy];
  query[(__bridge id)kSecReturnData] = @NO;

  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);
  resolve(status == errSecSuccess ? @YES : @NO);
}

- (void)deleteSecret:(NSString *)keyId
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  // Idempotent: errSecItemNotFound is success for a teardown path.
  SecItemDelete((__bridge CFDictionaryRef)WKCiphertextQuery(keyId));
  SecItemDelete((__bridge CFDictionaryRef)WKPublicKeyQuery(keyId));
  [self deleteKeyMaterial:keyId];
  resolve(nil);
}

- (void)deleteKeyMaterial:(NSString *)keyId
{
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrApplicationTag : WKKeyTag(keyId),
    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
  };
  SecItemDelete((__bridge CFDictionaryRef)query);
}


#pragma mark - v0.3 secp256k1

/** Uncompressed SEC1: 0x04 || X || Y, 65 bytes. */
static NSData *_Nullable WKPublicKeyFromPrivate(NSData *privateKey)
{
  secp256k1_context *ctx = WKSecpContext();
  secp256k1_pubkey pubkey;

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char *)privateKey.bytes)) {
    return nil;
  }

  uint8_t serialized[65];
  size_t length = sizeof(serialized);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &length, &pubkey,
                                     SECP256K1_EC_UNCOMPRESSED)) {
    return nil;
  }

  return [NSData dataWithBytes:serialized length:length];
}

- (void)persistPublicKey:(NSData *)publicKey forKeyId:(NSString *)keyId
{
  NSMutableDictionary *item = [WKPublicKeyQuery(keyId) mutableCopy];
  item[(__bridge id)kSecValueData] = publicKey;
  // No access control: a public key is not secret, and prompting to read your
  // own address would be hostile. Device-only so it does not sync.
  item[(__bridge id)kSecAttrAccessible] =
      (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;

  SecItemDelete((__bridge CFDictionaryRef)WKPublicKeyQuery(keyId));
  SecItemAdd((__bridge CFDictionaryRef)item, NULL);
}

/** Shared tail of generateKey and importPrivateKey. */
- (void)wrapPrivateKey:(NSData *)privateKey
                 keyId:(NSString *)keyId
                policy:(NSString *)policy
          invalidation:(NSString *)invalidation
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject
{
  NSData *publicKey = WKPublicKeyFromPrivate(privateKey);
  if (publicKey == nil) {
    reject(WKCodeInvalidKey, @"Could not derive a public key from this private key.", nil);
    return;
  }

  NSString *secretHex = WKHexFromData(privateKey);
  NSString *publicKeyHex = WKHexFromData(publicKey);

  [self storeSecretInternal:keyId
                  secretHex:secretHex
                     policy:policy
               invalidation:invalidation
                  onSuccess:^{
                    // Recorded only after wrapping succeeded, so a stored
                    // public key always implies a retrievable private one.
                    [self persistPublicKey:publicKey forKeyId:keyId];
                    resolve(publicKeyHex);
                  }
                    onError:^(NSString *code, NSString *message) {
                      reject(code, message, nil);
                    }];
}

- (void)generateKey:(NSString *)keyId
             policy:(NSString *)policy
       invalidation:(NSString *)invalidation
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  secp256k1_context *ctx = WKSecpContext();
  uint8_t seckey[32];

  // Rejection sampling against the curve order rather than reduction, which
  // would bias the distribution toward small keys. Entropy is the platform
  // CSPRNG — never JS, whose PRNG is not cryptographically secure.
  BOOL valid = NO;
  for (int attempt = 0; attempt < 256 && !valid; attempt++) {
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(seckey), seckey) != errSecSuccess) {
      WKSecureZero(seckey, sizeof(seckey));
      reject(WKCodeStorageError, @"The system random number generator failed.", nil);
      return;
    }
    valid = secp256k1_ec_seckey_verify(ctx, seckey) == 1;
  }

  if (!valid) {
    WKSecureZero(seckey, sizeof(seckey));
    reject(WKCodeStorageError, @"Could not generate a valid private key.", nil);
    return;
  }

  NSData *privateKey = [NSData dataWithBytes:seckey length:sizeof(seckey)];
  WKSecureZero(seckey, sizeof(seckey));

  [self wrapPrivateKey:privateKey
                 keyId:keyId
                policy:policy
          invalidation:invalidation
               resolve:resolve
                reject:reject];
}

- (void)importPrivateKey:(NSString *)keyId
           privateKeyHex:(NSString *)privateKeyHex
                  policy:(NSString *)policy
            invalidation:(NSString *)invalidation
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject
{
  NSData *privateKey = WKDataFromHex(privateKeyHex);
  if (privateKey == nil || privateKey.length != 32) {
    reject(WKCodeInvalidKey, @"A private key must be exactly 32 bytes of hex.", nil);
    return;
  }

  // Zero and anything at or above the curve order are not merely malformed —
  // they yield signatures that verify against nothing. Rejected, not clamped.
  if (secp256k1_ec_seckey_verify(WKSecpContext(), (const unsigned char *)privateKey.bytes) != 1) {
    reject(WKCodeInvalidKey, @"The private key must be in [1, n-1].", nil);
    return;
  }

  [self wrapPrivateKey:privateKey
                 keyId:keyId
                policy:policy
          invalidation:invalidation
               resolve:resolve
                reject:reject];
}

- (void)getPublicKey:(NSString *)keyId
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *query = [WKPublicKeyQuery(keyId) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;

  CFTypeRef stored = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &stored);

  if (status != errSecSuccess) {
    reject(WKCodeKeyNotFound, @"No key is stored under this keyId.", nil);
    return;
  }

  resolve(WKHexFromData(CFBridgingRelease(stored)));
}

- (void)signDigest:(NSString *)keyId
         digestHex:(NSString *)digestHex
            reason:(NSString *)reason
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  NSData *digest = WKDataFromHex(digestHex);
  if (digest == nil || digest.length != 32) {
    reject(WKCodeInvalidKey, @"A digest must be exactly 32 bytes of hex.", nil);
    return;
  }

  [self getSecretInternal:keyId
                   reason:reason
                onSuccess:^(NSData *privateKey) {
                  secp256k1_context *ctx = WKSecpContext();
                  secp256k1_ecdsa_recoverable_signature signature;

                  // The nonce is RFC 6979 deterministic by default. A repeated
                  // or predictable nonce reveals the private key algebraically,
                  // so this must never be supplied by hand.
                  if (!secp256k1_ecdsa_sign_recoverable(
                          ctx, &signature,
                          (const unsigned char *)digest.bytes,
                          (const unsigned char *)privateKey.bytes, NULL, NULL)) {
                    reject(WKCodeStorageError, @"Could not sign the digest.", nil);
                    return;
                  }

                  uint8_t compact[64];
                  int recid = 0;
                  secp256k1_ecdsa_recoverable_signature_serialize_compact(
                      ctx, compact, &recid, &signature);

                  // libsecp256k1 already emits the low-s form required by
                  // EIP-2, negating s and flipping recid when needed, so no
                  // separate normalization step is correct here.
                  uint8_t result[65];
                  memcpy(result, compact, 64);
                  result[64] = (uint8_t)(recid + 27);

                  NSData *serialized = [NSData dataWithBytes:result length:sizeof(result)];
                  WKSecureZero(compact, sizeof(compact));

                  resolve(WKHexFromData(serialized));
                }
                  onError:^(NSString *code, NSString *message) {
                    reject(code, message, nil);
                  }];
}

- (void)exportPrivateKey:(NSString *)keyId
                  reason:(NSString *)reason
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject
{
  [self getSecretInternal:keyId
                   reason:reason
                onSuccess:^(NSData *privateKey) {
                  resolve(WKHexFromData(privateKey));
                }
                  onError:^(NSString *code, NSString *message) {
                    reject(code, message, nil);
                  }];
}

#pragma mark - TurboModule

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeWalletKeystoreSpecJSI>(params);
}

+ (NSString *)moduleName
{
  return @"WalletKeystore";
}

@end
