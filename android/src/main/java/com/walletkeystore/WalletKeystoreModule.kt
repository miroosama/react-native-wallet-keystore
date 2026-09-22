package com.walletkeystore

import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.UiThreadUtil
import java.util.concurrent.atomic.AtomicBoolean

class WalletKeystoreModule(reactContext: ReactApplicationContext) :
  NativeWalletKeystoreSpec(reactContext) {

  /**
   * Ensures a promise is settled exactly once.
   *
   * BiometricPrompt can deliver a terminal callback while an earlier failure
   * path is already unwinding — a cancel racing an error, most often. Settling
   * a React Native promise twice throws, so the race is collapsed here rather
   * than guarded at each call site.
   */
  private class PromiseGuard(private val promise: Promise) {
    private val settled = AtomicBoolean(false)

    fun resolve(value: Any?) {
      if (settled.compareAndSet(false, true)) promise.resolve(value)
    }

    fun reject(code: String, message: String) {
      if (settled.compareAndSet(false, true)) promise.reject(code, message)
    }
  }

  override fun getBiometryType(promise: Promise) {
    val pm = reactApplicationContext.packageManager

    // PackageManager reports hardware presence only — Android has no API that
    // reveals which modality is actually enrolled. When several are present we
    // cannot attribute an authentication to one of them, so report the generic
    // type instead of guessing.
    val hasFingerprint = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
    val hasFace =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        pm.hasSystemFeature(PackageManager.FEATURE_FACE)
    val hasIris =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        pm.hasSystemFeature(PackageManager.FEATURE_IRIS)

    val present = listOf(hasFingerprint to "fingerprint", hasFace to "face", hasIris to "iris")
      .filter { it.first }
      .map { it.second }

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

    if (policy == POLICY_NONE) {
      guard.resolve(true)
      return
    }

    if (reason.isBlank()) {
      guard.reject(CODE_UNKNOWN, "A non-empty `reason` is required to authenticate.")
      return
    }

    // Null when the app is backgrounded, and not a FragmentActivity if the host
    // app uses a plain Activity. BiometricPrompt requires one, so both are the
    // same failure. `is` covers null as well.
    val activity = reactApplicationContext.currentActivity
    if (activity !is FragmentActivity) {
      guard.reject(
        CODE_NOT_AVAILABLE,
        "A foreground FragmentActivity is required to show the biometric prompt."
      )
      return
    }

    val authenticators = authenticatorsFor(policy)

    when (val status = BiometricManager.from(reactApplicationContext).canAuthenticate(authenticators)) {
      BiometricManager.BIOMETRIC_SUCCESS -> Unit
      else -> {
        guard.reject(mapAvailability(status), availabilityMessage(status, authenticators))
        return
      }
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

          // onAuthenticationFailed is intentionally not overridden. It fires on
          // every rejected attempt — a non-matching fingerprint — while the
          // prompt stays up for a retry. Settling there would end the flow on
          // the user's first fumble and leave the prompt orphaned on screen.
        }

        val prompt = BiometricPrompt(
          activity,
          ContextCompat.getMainExecutor(activity),
          callback
        )
        prompt.authenticate(buildPromptInfo(reason, authenticators))
      } catch (e: Exception) {
        guard.reject(CODE_UNKNOWN, e.message ?: "Failed to present the biometric prompt.")
      }
    }
  }

  private fun buildPromptInfo(
    reason: String,
    authenticators: Int
  ): BiometricPrompt.PromptInfo {
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

  // BIOMETRIC_STRONG or DEVICE_CREDENTIAL is rejected by setAllowedAuthenticators
  // below API 30, so the pre-30 path degrades to biometric-only rather than
  // silently accepting a weaker credential: a caller asking for
  // 'biometricOrPasscode' on API 24-29 gets a biometric prompt, and
  // NOT_ENROLLED if nothing is enrolled.
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


  // ---------------------------------------------------------------------------
  // Secret storage
  // ---------------------------------------------------------------------------

  /**
   * Note the platform asymmetry against iOS: there, encryption uses only the
   * public half of an enclave keypair and needs no authentication. Android's
   * wrapping key is symmetric AES-GCM, and `setUserAuthenticationRequired(true)`
   * governs every use of it, so storing prompts too. Making storage silent here
   * would mean dropping the auth requirement from the key entirely, which is
   * the one property worth having.
   */
  override fun storeSecret(
    keyId: String,
    secretHex: String,
    policy: String,
    invalidation: String,
    promise: Promise
  ) {
    val guard = PromiseGuard(promise)

    val secret = WalletKeystoreCrypto.fromHex(secretHex)
    if (secret == null) {
      guard.reject(CODE_UNKNOWN, "`secretHex` must be a non-empty hex string.")
      return
    }

    // Overwriting a wallet key has to be deliberate.
    if (WalletKeystoreCrypto.hasRecord(reactApplicationContext, keyId) ||
      WalletKeystoreCrypto.hasKey(keyId)
    ) {
      guard.reject(CODE_KEY_ALREADY_EXISTS, "A secret is already stored under this keyId.")
      return
    }

    val generated = try {
      WalletKeystoreCrypto.generateKey(keyId, policy, invalidation)
    } catch (e: Exception) {
      guard.reject(CODE_STORAGE_ERROR, e.message ?: "Could not create the wrapping key.")
      return
    }

    val cipher = try {
      WalletKeystoreCrypto.encryptCipher(generated.key)
    } catch (e: Exception) {
      WalletKeystoreCrypto.deleteKey(keyId)
      guard.reject(classify(e), e.message ?: "Could not initialize encryption.")
      return
    }

    if (policy == POLICY_NONE) {
      finishStore(guard, keyId, secret, cipher)
      return
    }

    withPrompt(
      guard,
      reason = "Store your wallet key",
      policy = policy,
      cipher = cipher,
      onAuthenticated = { authenticated ->
        finishStore(guard, keyId, secret, authenticated)
      },
      onSetupFailure = { WalletKeystoreCrypto.deleteKey(keyId) }
    )
  }

  private fun finishStore(
    guard: PromiseGuard,
    keyId: String,
    secret: ByteArray,
    cipher: Cipher
  ) {
    try {
      val ciphertext = cipher.doFinal(secret)
      WalletKeystoreCrypto.writeRecord(
        reactApplicationContext,
        keyId,
        cipher.iv,
        ciphertext
      )
      guard.resolve(null)
    } catch (e: Exception) {
      // Never leave a key behind with no ciphertext — the id would look taken
      // forever and storeSecret would keep rejecting KEY_ALREADY_EXISTS.
      WalletKeystoreCrypto.deleteKey(keyId)
      WalletKeystoreCrypto.deleteRecord(reactApplicationContext, keyId)
      guard.reject(classify(e), e.message ?: "Could not encrypt the secret.")
    } finally {
      secret.fill(0)
    }
  }

  override fun getSecret(keyId: String, reason: String, promise: Promise) {
    val guard = PromiseGuard(promise)

    if (reason.isBlank()) {
      guard.reject(CODE_UNKNOWN, "A non-empty `reason` is required to read a secret.")
      return
    }

    val record = WalletKeystoreCrypto.readRecord(reactApplicationContext, keyId)
    if (record == null) {
      guard.reject(CODE_KEY_NOT_FOUND, "No secret is stored under this keyId.")
      return
    }
    val (iv, ciphertext) = record

    val key = try {
      WalletKeystoreCrypto.loadKey(keyId)
    } catch (e: Exception) {
      guard.reject(classify(e), e.message ?: "Could not load the wrapping key.")
      return
    }

    if (key == null) {
      guard.reject(CODE_KEY_NOT_FOUND, "The wrapping key for this keyId is missing.")
      return
    }

    // Cipher.init is where a key pinned to a changed biometric enrollment
    // throws, so this is where KEY_INVALIDATED is detected.
    val cipher = try {
      WalletKeystoreCrypto.decryptCipher(key, iv)
    } catch (e: Exception) {
      guard.reject(classify(e), e.message ?: "The wrapping key is no longer usable.")
      return
    }

    // Asked of the key rather than discovered by attempting the operation: a
    // failed doFinal leaves the Cipher unusable, so it could not then be handed
    // to the CryptoObject below.
    if (!WalletKeystoreCrypto.requiresAuth(key)) {
      try {
        val plaintext = cipher.doFinal(ciphertext)
        guard.resolve(WalletKeystoreCrypto.hex(plaintext))
        plaintext.fill(0)
      } catch (e: Exception) {
        guard.reject(classify(e), e.message ?: "Could not decrypt the secret.")
      }
      return
    }

    // The CryptoObject is what makes this a real boundary rather than a check:
    // the Cipher stays unusable until the OS validates the user, so a
    // compromised JS bundle cannot skip it by faking a boolean.
    withPrompt(
      guard,
      reason = reason,
      policy = inferPolicy(),
      cipher = cipher,
      onAuthenticated = { authenticated ->
        try {
          val plaintext = authenticated.doFinal(ciphertext)
          guard.resolve(WalletKeystoreCrypto.hex(plaintext))
          plaintext.fill(0)
        } catch (e: Exception) {
          guard.reject(classify(e), e.message ?: "Could not decrypt the secret.")
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
    WalletKeystoreCrypto.deleteKey(keyId)
    promise.resolve(null)
  }

  /**
   * The key already encodes which authenticators it accepts, and the prompt
   * only has to be permissive enough to satisfy it. Asking for both is correct
   * for a key that accepts either and harmless for one that does not, since the
   * Keystore — not the prompt — is the thing enforcing the constraint.
   */
  private fun inferPolicy(): String = "biometricOrPasscode"

  /** Shared BiometricPrompt presentation for the crypto-bound operations. */
  private fun withPrompt(
    guard: PromiseGuard,
    reason: String,
    policy: String,
    cipher: Cipher,
    onAuthenticated: (Cipher) -> Unit,
    onSetupFailure: () -> Unit = {}
  ) {
    val activity = reactApplicationContext.currentActivity
    if (activity !is FragmentActivity) {
      onSetupFailure()
      guard.reject(
        CODE_NOT_AVAILABLE,
        "A foreground FragmentActivity is required to show the biometric prompt."
      )
      return
    }

    val authenticators = authenticatorsFor(policy)

    val status = BiometricManager.from(reactApplicationContext).canAuthenticate(authenticators)
    if (status != BiometricManager.BIOMETRIC_SUCCESS) {
      onSetupFailure()
      guard.reject(mapAvailability(status), availabilityMessage(status, authenticators))
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
              guard.reject(CODE_UNKNOWN, "The authenticated cipher was not returned.")
              return
            }
            onAuthenticated(authenticated)
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            onSetupFailure()
            guard.reject(mapAuthError(errorCode), errString.toString())
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
        guard.reject(CODE_UNKNOWN, e.message ?: "Failed to present the biometric prompt.")
      }
    }
  }

  private fun classify(t: Throwable): String = when {
    WalletKeystoreCrypto.isInvalidated(t) -> CODE_KEY_INVALIDATED
    WalletKeystoreCrypto.isNotAuthenticated(t) -> CODE_NOT_ENROLLED
    else -> CODE_STORAGE_ERROR
  }

  companion object {
    const val NAME = NativeWalletKeystoreSpec.NAME

    internal const val POLICY_BIOMETRIC_ONLY = "biometricOnly"
    internal const val POLICY_NONE = "none"
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
  }
}
