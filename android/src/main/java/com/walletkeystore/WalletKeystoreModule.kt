package com.walletkeystore

import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.UiThreadUtil
import java.math.BigInteger
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher

class WalletKeystoreModule(reactContext: ReactApplicationContext) :
  NativeWalletKeystoreSpec(reactContext) {

  /**
   * Where an operation's result goes. Signing reuses the storage operations and
   * needs to intercept their result, and this avoids hand-rolling a `Promise`
   * stand-in that would drift from React Native's interface.
   */
  private interface Settler {
    fun resolve(value: Any?)
    fun reject(code: String, message: String)
  }

  /**
   * Settles exactly once. BiometricPrompt can deliver a terminal callback while
   * an earlier failure is still unwinding, and settling twice throws.
   */
  private class PromiseGuard(private val promise: Promise) : Settler {
    private val settled = AtomicBoolean(false)

    override fun resolve(value: Any?) {
      if (settled.compareAndSet(false, true)) promise.resolve(value)
    }

    override fun reject(code: String, message: String) {
      if (settled.compareAndSet(false, true)) promise.reject(code, message)
    }
  }

  /** Routes a nested operation's outcome back into the caller's own handling. */
  private class Relay(
    private val onResolve: (Any?) -> Unit,
    private val onReject: (String, String) -> Unit,
  ) : Settler {
    override fun resolve(value: Any?) = onResolve(value)
    override fun reject(code: String, message: String) = onReject(code, message)
  }

  // ---------------------------------------------------------------------------
  // Authentication
  // ---------------------------------------------------------------------------

  override fun getBiometryType(promise: Promise) {
    val pm = reactApplicationContext.packageManager

    // PackageManager reports hardware presence only; Android has no API for
    // which modality is enrolled. Several present means we cannot attribute.
    val hasFingerprint = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
    val hasFace =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        pm.hasSystemFeature(PackageManager.FEATURE_FACE)
    val hasIris =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        pm.hasSystemFeature(PackageManager.FEATURE_IRIS)

    val present = listOf(
      hasFingerprint to "fingerprint",
      hasFace to "face",
      hasIris to "iris"
    ).filter { it.first }.map { it.second }

    promise.resolve(
      when {
        present.isEmpty() -> "none"
        present.size == 1 -> present.first()
        else -> "biometric"
      }
    )
  }

  override fun authenticate(reason: String, policy: String, promise: Promise) {
    val guard = PromiseGuard(promise)

    if (reason.isBlank()) {
      guard.reject(CODE_UNKNOWN, "A non-empty `reason` is required to authenticate.")
      return
    }

    val activity = reactApplicationContext.currentActivity
    if (activity !is FragmentActivity) {
      guard.reject(
        CODE_NOT_AVAILABLE,
        "A foreground FragmentActivity is required to show the biometric prompt."
      )
      return
    }

    val authenticators = authenticatorsFor(policy)
    val status = BiometricManager.from(reactApplicationContext).canAuthenticate(authenticators)
    if (status != BiometricManager.BIOMETRIC_SUCCESS) {
      guard.reject(mapAvailability(status), availabilityMessage(status, authenticators))
      return
    }

    // BiometricPrompt must be constructed and shown on the main thread. The
    // authentication itself runs off it, and the callback returns here.
    UiThreadUtil.runOnUiThread {
      try {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            guard.resolve(true)
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            guard.reject(mapAuthError(errorCode), errString.toString())
          }

          // onAuthenticationFailed is deliberately not overridden: it fires per
          // rejected attempt while the prompt stays up, so settling there would
          // end the flow on the user's first fumble.
        }

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
          .authenticate(buildPromptInfo(reason, authenticators))
      } catch (e: Exception) {
        guard.reject(CODE_UNKNOWN, e.message ?: "Failed to present the biometric prompt.")
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Secret storage
  // ---------------------------------------------------------------------------

  override fun storeSecret(
    keyId: String,
    secretHex: String,
    policy: String,
    invalidation: String,
    promise: Promise
  ) = storeSecretInto(keyId, secretHex, policy, invalidation, PromiseGuard(promise))

  /**
   * Unlike iOS, storing prompts here: the wrapping key is symmetric, and
   * `setUserAuthenticationRequired(true)` governs every use of it. Silent
   * storage would mean dropping that requirement entirely.
   */
  private fun storeSecretInto(
    keyId: String,
    secretHex: String,
    policy: String,
    invalidation: String,
    settler: Settler
  ) {
    val secret = WalletKeystoreCrypto.fromHex(secretHex)
    if (secret == null) {
      settler.reject(CODE_UNKNOWN, "`secretHex` must be a non-empty hex string.")
      return
    }

    // Overwriting a wallet key has to be deliberate.
    if (WalletKeystoreCrypto.hasRecord(reactApplicationContext, keyId) ||
      WalletKeystoreCrypto.hasKey(keyId)
    ) {
      settler.reject(CODE_KEY_ALREADY_EXISTS, "A secret is already stored under this keyId.")
      return
    }

    val generated = try {
      WalletKeystoreCrypto.generateKey(keyId, policy, invalidation)
    } catch (e: Exception) {
      settler.reject(CODE_STORAGE_ERROR, e.message ?: "Could not create the wrapping key.")
      return
    }

    val cipher = try {
      WalletKeystoreCrypto.encryptCipher(generated.key)
    } catch (e: Exception) {
      WalletKeystoreCrypto.deleteKey(keyId)
      settler.reject(classify(e), e.message ?: "Could not initialize encryption.")
      return
    }

    withPrompt(
      settler,
      reason = "Store your wallet key",
      policy = policy,
      cipher = cipher,
      onAuthenticated = { authenticated -> finishStore(settler, keyId, secret, authenticated) },
      onSetupFailure = { WalletKeystoreCrypto.deleteKey(keyId) }
    )
  }

  private fun finishStore(
    settler: Settler,
    keyId: String,
    secret: ByteArray,
    cipher: Cipher
  ) {
    try {
      val ciphertext = cipher.doFinal(secret)
      WalletKeystoreCrypto.writeRecord(reactApplicationContext, keyId, cipher.iv, ciphertext)
      settler.resolve(null)
    } catch (e: Exception) {
      // Never leave a key behind with no ciphertext — the id would look taken
      // forever and storeSecret would keep rejecting KEY_ALREADY_EXISTS.
      WalletKeystoreCrypto.deleteKey(keyId)
      WalletKeystoreCrypto.deleteRecord(reactApplicationContext, keyId)
      settler.reject(classify(e), e.message ?: "Could not encrypt the secret.")
    } finally {
      secret.fill(0)
    }
  }

  override fun getSecret(keyId: String, reason: String, promise: Promise) =
    getSecretInto(keyId, reason, PromiseGuard(promise))

  private fun getSecretInto(keyId: String, reason: String, settler: Settler) {
    if (reason.isBlank()) {
      settler.reject(CODE_UNKNOWN, "A non-empty `reason` is required to read a secret.")
      return
    }

    val record = WalletKeystoreCrypto.readRecord(reactApplicationContext, keyId)
    if (record == null) {
      settler.reject(CODE_KEY_NOT_FOUND, "No secret is stored under this keyId.")
      return
    }
    val (iv, ciphertext) = record

    val key = try {
      WalletKeystoreCrypto.loadKey(keyId)
    } catch (e: Exception) {
      settler.reject(classify(e), e.message ?: "Could not load the wrapping key.")
      return
    }

    if (key == null) {
      // Ciphertext present but wrapping key gone: unrecoverable, not absent.
      // Removing the device lock deletes auth-bound keys outright rather than
      // throwing KeyPermanentlyInvalidatedException, so it lands here.
      settler.reject(
        CODE_KEY_INVALIDATED,
        "The wrapping key no longer exists; this secret cannot be recovered."
      )
      return
    }

    // Cipher.init is where a key pinned to a changed biometric enrollment
    // throws, so this is where KEY_INVALIDATED is detected.
    val cipher = try {
      WalletKeystoreCrypto.decryptCipher(key, iv)
    } catch (e: Exception) {
      settler.reject(classify(e), e.message ?: "The wrapping key is no longer usable.")
      return
    }

    // Asked of the key rather than discovered by attempting the operation: a
    // failed doFinal leaves the Cipher unusable, so it could not then be handed
    // to the CryptoObject below.
    if (!WalletKeystoreCrypto.requiresAuth(key)) {
      try {
        val plaintext = cipher.doFinal(ciphertext)
        settler.resolve(WalletKeystoreCrypto.hex(plaintext))
        plaintext.fill(0)
      } catch (e: Exception) {
        settler.reject(classify(e), e.message ?: "Could not decrypt the secret.")
      }
      return
    }

    // The CryptoObject is what makes this a real boundary rather than a check:
    // the Cipher stays unusable until the OS validates the user, so a
    // compromised JS bundle cannot skip it by faking a boolean.
    withPrompt(
      settler,
      reason = reason,
      policy = POLICY_BIOMETRIC_OR_PASSCODE,
      cipher = cipher,
      onAuthenticated = { authenticated ->
        try {
          val plaintext = authenticated.doFinal(ciphertext)
          settler.resolve(WalletKeystoreCrypto.hex(plaintext))
          plaintext.fill(0)
        } catch (e: Exception) {
          settler.reject(classify(e), e.message ?: "Could not decrypt the secret.")
        }
      }
    )
  }

  override fun hasSecret(keyId: String, promise: Promise) {
    promise.resolve(WalletKeystoreCrypto.hasRecord(reactApplicationContext, keyId))
  }

  override fun deleteSecret(keyId: String, promise: Promise) {
    // Idempotent: a missing keyId is success for a teardown path.
    WalletKeystoreCrypto.deleteRecord(reactApplicationContext, keyId)
    WalletKeystoreCrypto.deletePublicKey(reactApplicationContext, keyId)
    WalletKeystoreCrypto.deleteKey(keyId)
    promise.resolve(null)
  }

  // ---------------------------------------------------------------------------
  // secp256k1
  // ---------------------------------------------------------------------------

  override fun generateKey(
    keyId: String,
    policy: String,
    invalidation: String,
    promise: Promise
  ) {
    val guard = PromiseGuard(promise)

    // Entropy from SecureRandom, never from JS. The private key goes straight
    // into the wrapping path and never crosses the bridge.
    val privateKey = try {
      Secp256k1.generatePrivateKey()
    } catch (e: Exception) {
      guard.reject(CODE_STORAGE_ERROR, e.message ?: "Could not generate a key.")
      return
    }

    wrapPrivateKey(keyId, privateKey, policy, invalidation, guard)
  }

  override fun importPrivateKey(
    keyId: String,
    privateKeyHex: String,
    policy: String,
    invalidation: String,
    promise: Promise
  ) {
    val guard = PromiseGuard(promise)

    val privateKey = WalletKeystoreCrypto.fromHex(privateKeyHex)
    if (privateKey == null || privateKey.size != 32) {
      guard.reject(CODE_INVALID_KEY, "A private key must be exactly 32 bytes of hex.")
      return
    }

    // Zero and anything at or above the curve order are not merely malformed:
    // they produce signatures that verify against nothing. Rejected, not clamped.
    if (!Secp256k1.isValidPrivateKey(BigInteger(1, privateKey))) {
      privateKey.fill(0)
      guard.reject(CODE_INVALID_KEY, "The private key must be in [1, n-1].")
      return
    }

    wrapPrivateKey(keyId, privateKey, policy, invalidation, guard)
  }

  /** Derives the public key, then stores the private key via the v0.2 path. */
  private fun wrapPrivateKey(
    keyId: String,
    privateKey: ByteArray,
    policy: String,
    invalidation: String,
    guard: Settler
  ) {
    val publicKeyHex = try {
      WalletKeystoreCrypto.hex(Secp256k1.publicKeyFrom(privateKey))
    } catch (e: Exception) {
      privateKey.fill(0)
      guard.reject(CODE_INVALID_KEY, e.message ?: "Could not derive the public key.")
      return
    }

    val hex = WalletKeystoreCrypto.hex(privateKey)
    privateKey.fill(0)

    storeSecretInto(
      keyId, hex, policy, invalidation,
      Relay(
        onResolve = {
          // Recorded only after the wrapping succeeded, so a stored public key
          // always implies a retrievable private one.
          WalletKeystoreCrypto.writePublicKey(reactApplicationContext, keyId, publicKeyHex)
          guard.resolve(publicKeyHex)
        },
        onReject = { code, message -> guard.reject(code, message) }
      )
    )
  }

  override fun getPublicKey(keyId: String, promise: Promise) {
    val publicKey = WalletKeystoreCrypto.readPublicKey(reactApplicationContext, keyId)
    if (publicKey == null) {
      promise.reject(CODE_KEY_NOT_FOUND, "No key is stored under this keyId.")
      return
    }
    promise.resolve(publicKey)
  }

  override fun signDigest(
    keyId: String,
    digestHex: String,
    reason: String,
    promise: Promise
  ) {
    val guard = PromiseGuard(promise)

    val digest = WalletKeystoreCrypto.fromHex(digestHex)
    if (digest == null || digest.size != 32) {
      guard.reject(CODE_INVALID_KEY, "A digest must be exactly 32 bytes of hex.")
      return
    }

    withUnwrappedKey(keyId, reason, guard) { privateKey ->
      try {
        guard.resolve(WalletKeystoreCrypto.hex(Secp256k1.sign(digest, privateKey)))
      } catch (e: Exception) {
        guard.reject(CODE_STORAGE_ERROR, e.message ?: "Could not sign the digest.")
      }
    }
  }

  override fun exportPrivateKey(keyId: String, reason: String, promise: Promise) {
    val guard = PromiseGuard(promise)
    withUnwrappedKey(keyId, reason, guard) { privateKey ->
      guard.resolve(WalletKeystoreCrypto.hex(privateKey))
    }
  }

  /**
   * Authenticates, decrypts, hands over the raw key, then zeroes it.
   *
   * The zeroing is best-effort by nature — see the README. It shrinks the window
   * in which the key sits in memory; in a managed runtime it cannot close it.
   */
  private fun withUnwrappedKey(
    keyId: String,
    reason: String,
    guard: Settler,
    use: (ByteArray) -> Unit
  ) {
    getSecretInto(
      keyId, reason,
      Relay(
        onResolve = { value ->
          val privateKey = (value as? String)?.let { WalletKeystoreCrypto.fromHex(it) }
          if (privateKey == null) {
            guard.reject(CODE_STORAGE_ERROR, "The stored key is missing or malformed.")
          } else {
            try {
              use(privateKey)
            } finally {
              privateKey.fill(0)
            }
          }
        },
        onReject = { code, message -> guard.reject(code, message) }
      )
    )
  }

  // ---------------------------------------------------------------------------
  // Prompt plumbing
  // ---------------------------------------------------------------------------

  /** Shared BiometricPrompt presentation for the crypto-bound operations. */
  private fun withPrompt(
    settler: Settler,
    reason: String,
    policy: String,
    cipher: Cipher,
    onAuthenticated: (Cipher) -> Unit,
    onSetupFailure: () -> Unit = {}
  ) {
    val activity = reactApplicationContext.currentActivity
    if (activity !is FragmentActivity) {
      onSetupFailure()
      settler.reject(
        CODE_NOT_AVAILABLE,
        "A foreground FragmentActivity is required to show the biometric prompt."
      )
      return
    }

    val authenticators = authenticatorsFor(policy)
    val status = BiometricManager.from(reactApplicationContext).canAuthenticate(authenticators)
    if (status != BiometricManager.BIOMETRIC_SUCCESS) {
      onSetupFailure()
      settler.reject(mapAvailability(status), availabilityMessage(status, authenticators))
      return
    }

    UiThreadUtil.runOnUiThread {
      try {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            // The Cipher handed back by the framework is the authenticated one.
            val authenticated = result.cryptoObject?.cipher
            if (authenticated == null) {
              onSetupFailure()
              settler.reject(CODE_UNKNOWN, "The authenticated cipher was not returned.")
              return
            }
            onAuthenticated(authenticated)
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            onSetupFailure()
            settler.reject(mapAuthError(errorCode), errString.toString())
          }

          // onAuthenticationFailed is intentionally not overridden — see
          // authenticate() above.
        }

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
          .authenticate(
            buildPromptInfo(reason, authenticators),
            BiometricPrompt.CryptoObject(cipher)
          )
      } catch (e: Exception) {
        onSetupFailure()
        settler.reject(CODE_UNKNOWN, e.message ?: "Failed to present the biometric prompt.")
      }
    }
  }

  private fun buildPromptInfo(reason: String, authenticators: Int): BiometricPrompt.PromptInfo {
    val builder = BiometricPrompt.PromptInfo.Builder()
      .setTitle(reason)
      .setAllowedAuthenticators(authenticators)

    // The framework supplies its own device-credential affordance, and setting
    // a negative button alongside DEVICE_CREDENTIAL throws. When biometrics are
    // the only authenticator the negative button is mandatory instead — there
    // would otherwise be no way to dismiss the prompt.
    if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
      builder.setNegativeButtonText("Cancel")
    }

    return builder.build()
  }

  // setAllowedAuthenticators rejects BIOMETRIC_STRONG or DEVICE_CREDENTIAL below
  // API 30, so API 24-29 degrades to biometric-only rather than silently
  // accepting a weaker credential.
  private fun authenticatorsFor(policy: String): Int =
    WalletKeystoreCrypto.authenticatorsFor(policy)

  private fun mapAvailability(status: Int): String = when (status) {
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> CODE_NOT_AVAILABLE
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> CODE_NOT_ENROLLED
    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> CODE_NOT_AVAILABLE
    else -> CODE_UNKNOWN
  }

  private fun availabilityMessage(status: Int, authenticators: Int): String = when (status) {
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
      "This device has no biometric hardware."
    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
      "Biometric hardware is currently unavailable."
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
      // A device credential may well be enrolled while this still fails under
      // 'biometricOnly', so the message has to name only what was actually
      // asked for. Saying "or device credential" there sends the user to
      // Settings to re-add a PIN they already have.
      if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL != 0) {
        "No biometric or device credential is enrolled."
      } else {
        "No biometric is enrolled."
      }
    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
      "A security update is required before biometrics can be used."
    else -> "Biometric authentication is unavailable (status $status)."
  }

  private fun mapAuthError(errorCode: Int): String = when (errorCode) {
    BiometricPrompt.ERROR_HW_NOT_PRESENT,
    BiometricPrompt.ERROR_HW_UNAVAILABLE -> CODE_NOT_AVAILABLE

    BiometricPrompt.ERROR_NO_BIOMETRICS -> CODE_NOT_ENROLLED

    // ERROR_NEGATIVE_BUTTON is the Cancel button; ERROR_USER_CANCELED is a
    // dismissal. Both are the user declining, so both stay retryable.
    BiometricPrompt.ERROR_USER_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> CODE_USER_CANCELED

    BiometricPrompt.ERROR_LOCKOUT -> CODE_LOCKOUT
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> CODE_LOCKOUT_PERMANENT

    // ERROR_CANCELED is the system tearing the prompt down; ERROR_TIMEOUT is it
    // expiring untouched. Neither is user intent.
    BiometricPrompt.ERROR_CANCELED,
    BiometricPrompt.ERROR_TIMEOUT -> CODE_SYSTEM_CANCEL

    else -> CODE_UNKNOWN
  }

  private fun classify(t: Throwable): String = when {
    WalletKeystoreCrypto.isInvalidated(t) -> CODE_KEY_INVALIDATED
    WalletKeystoreCrypto.isNotAuthenticated(t) -> CODE_NOT_ENROLLED
    else -> CODE_STORAGE_ERROR
  }

  companion object {
    const val NAME = NativeWalletKeystoreSpec.NAME

    internal const val POLICY_BIOMETRIC_ONLY = "biometricOnly"
    internal const val POLICY_BIOMETRIC_OR_PASSCODE = "biometricOrPasscode"
    internal const val INVALIDATION_ON_ENROLLMENT_CHANGE = "onEnrollmentChange"

    private const val CODE_NOT_AVAILABLE = "NOT_AVAILABLE"
    private const val CODE_NOT_ENROLLED = "NOT_ENROLLED"
    private const val CODE_USER_CANCELED = "USER_CANCELED"
    private const val CODE_LOCKOUT = "LOCKOUT"
    private const val CODE_LOCKOUT_PERMANENT = "LOCKOUT_PERMANENT"
    private const val CODE_SYSTEM_CANCEL = "SYSTEM_CANCEL"
    private const val CODE_UNKNOWN = "UNKNOWN"
    private const val CODE_KEY_NOT_FOUND = "KEY_NOT_FOUND"
    private const val CODE_KEY_ALREADY_EXISTS = "KEY_ALREADY_EXISTS"
    private const val CODE_KEY_INVALIDATED = "KEY_INVALIDATED"
    private const val CODE_STORAGE_ERROR = "STORAGE_ERROR"
    private const val CODE_INVALID_KEY = "INVALID_KEY"
  }
}
