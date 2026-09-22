#import "WalletKeystore.h"

#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

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

static NSString *const WKKeychainService = @"com.walletkeystore.secret";
static NSString *const WKKeyTagPrefix = @"com.walletkeystore.wrap.";

@implementation WalletKeystore

#pragma mark - Error mapping

/**
 * Maps an LAError onto the cross-platform code set.
 *
 * There is no LOCKOUT_PERMANENT case: iOS resolves permanent biometric lockout
 * inside the system prompt by demanding the device passcode, so it never
 * surfaces the state to the app. Android's ERROR_LOCKOUT_PERMANENT has no iOS
 * counterpart, and faking one would be a lie.
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

    // The access control could not be satisfied by any enrolled credential.
    // After a biometric enrollment change against a .biometryCurrentSet key,
    // this is permanent: the key material is gone, not merely unavailable.
    case errSecAuthFailed:
      return WKCodeKeyInvalidated;

    case errSecInteractionNotAllowed:
      return WKCodeSystemCancel;

    default:
      return WKCodeStorageError;
  }
}

/**
 * SecKey operations report failures as a CFError that may carry either an
 * LAError or an OSStatus, depending on whether authentication or the keychain
 * itself failed. Both have to be unwrapped or a cancel reads as a storage bug.
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

  if (biometricOnly) {
    return invalidates ? kSecAccessControlBiometryCurrentSet
                       : kSecAccessControlBiometryAny;
  }

  if (invalidates) {
    // Biometrics pinned to the current enrollment, but the passcode remains a
    // route in — otherwise this would be indistinguishable from biometricOnly.
    return kSecAccessControlBiometryCurrentSet | kSecAccessControlOr |
           kSecAccessControlDevicePasscode;
  }

  return kSecAccessControlUserPresence;
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

  // A fresh context per call is a security requirement, not tidiness: a reused
  // LAContext can satisfy a later evaluation from a cached earlier success via
  // touchIDAuthenticationAllowableReuseDuration, which for a wallet would mean
  // signing without the user actually authenticating. Pinning the duration to
  // zero makes that explicit and survives the default changing.
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
  NSData *secret = WKDataFromHex(secretHex);
  if (secret == nil || secret.length == 0) {
    reject(WKCodeUnknown, @"`secretHex` must be a non-empty hex string.", nil);
    return;
  }

  // Overwriting a wallet key has to be deliberate, so an existing id is an
  // error rather than a silent replace.
  OSStatus existing = errSecSuccess;
  SecKeyRef existingKey = WKCopyPrivateKey(keyId, nil, &existing);
  if (existingKey != NULL) {
    CFRelease(existingKey);
    reject(WKCodeKeyAlreadyExists,
           @"A secret is already stored under this keyId.", nil);
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
    reject(WKCodeFromSecError(error),
           error.localizedDescription ?: @"Could not build access control.",
           error);
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
    reject(WKCodeFromSecError(error),
           error.localizedDescription ?: @"Could not create the wrapping key.",
           error);
    return;
  }

  SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
  CFRelease(privateKey);

  if (publicKey == NULL) {
    [self deleteKeyMaterial:keyId];
    reject(WKCodeStorageError, @"Could not derive the wrapping public key.", nil);
    return;
  }

  // Encryption uses only the public half, so it needs no authentication. Only
  // reading the secret back prompts the user.
  CFErrorRef encryptError = NULL;
  NSData *ciphertext = CFBridgingRelease(SecKeyCreateEncryptedData(
      publicKey,
      kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
      (__bridge CFDataRef)secret,
      &encryptError));
  CFRelease(publicKey);

  if (ciphertext == nil) {
    NSError *error = CFBridgingRelease(encryptError);
    [self deleteKeyMaterial:keyId];
    reject(WKCodeFromSecError(error),
           error.localizedDescription ?: @"Could not encrypt the secret.",
           error);
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
    reject(WKCodeFromOSStatus(addStatus),
           [NSString stringWithFormat:@"Could not store the ciphertext (%d).",
                                      (int)addStatus],
           nil);
    return;
  }

  resolve(nil);
}

- (void)getSecret:(NSString *)keyId
           reason:(NSString *)reason
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *query = [WKCiphertextQuery(keyId) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;

  CFTypeRef stored = NULL;
  OSStatus readStatus =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, &stored);

  if (readStatus != errSecSuccess) {
    reject(WKCodeFromOSStatus(readStatus),
           readStatus == errSecItemNotFound
               ? @"No secret is stored under this keyId."
               : @"Could not read the stored ciphertext.",
           nil);
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
      reject(WKCodeFromOSStatus(keyStatus),
             keyStatus == errSecItemNotFound
                 ? @"The wrapping key for this keyId is missing."
                 : @"Could not load the wrapping key.",
             nil);
      return;
    }

    CFErrorRef decryptError = NULL;
    NSData *plaintext = CFBridgingRelease(SecKeyCreateDecryptedData(
        privateKey,
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
        (__bridge CFDataRef)ciphertext,
        &decryptError));
    CFRelease(privateKey);

    if (plaintext == nil) {
      NSError *error = CFBridgingRelease(decryptError);
      reject(WKCodeFromSecError(error),
             error.localizedDescription ?: @"Could not decrypt the secret.",
             error);
      return;
    }

    NSString *hex = WKHexFromData(plaintext);

    // Best effort only. The NSData buffer is zeroed here, but the NSString
    // above is already immutable and heap-allocated, and the JS string it
    // becomes cannot be zeroed at all. This is why signDigest will exist.
    memset((void *)plaintext.bytes, 0, plaintext.length);

    resolve(hex);
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
