package com.walletkeystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricManager
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Keystore-backed wrapping keys and the ciphertext store.
 *
 * Separated from the module so the threading and promise handling stay in one
 * file and the crypto in another.
 */
internal object WalletKeystoreCrypto {

  const val ANDROID_KEYSTORE = "AndroidKeyStore"
  const val TRANSFORMATION = "AES/GCM/NoPadding"
  const val GCM_TAG_BITS = 128
  private const val PREFS = "com.walletkeystore.secrets"
  private const val KEY_PREFIX = "com.walletkeystore.wrap."
  private const val PUBLIC_KEY_PREFIX = "pub:"

  fun alias(keyId: String) = KEY_PREFIX + keyId

  private fun prefs(context: Context) =
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  // The payload is already encrypted by a hardware-bound key, so
  // EncryptedSharedPreferences would add a second layer over the same threat
  // model for no gain.
  fun readRecord(context: Context, keyId: String): Pair<ByteArray, ByteArray>? {
    val raw = prefs(context).getString(keyId, null) ?: return null
    val parts = raw.split(":")
    if (parts.size != 2) return null
    return try {
      Base64.decode(parts[0], Base64.NO_WRAP) to Base64.decode(parts[1], Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      null
    }
  }

  fun writeRecord(context: Context, keyId: String, iv: ByteArray, ciphertext: ByteArray) {
    val encoded = Base64.encodeToString(iv, Base64.NO_WRAP) + ":" +
      Base64.encodeToString(ciphertext, Base64.NO_WRAP)
    prefs(context).edit().putString(keyId, encoded).apply()
  }

  fun deleteRecord(context: Context, keyId: String) {
    prefs(context).edit().remove(keyId).apply()
  }

  fun hasRecord(context: Context, keyId: String) = prefs(context).contains(keyId)

  // The public key is stored in the clear, deliberately. Deriving it requires
  // the private key, and nobody should face a biometric prompt to look up their
  // own address.
  fun writePublicKey(context: Context, keyId: String, publicKeyHex: String) {
    prefs(context).edit().putString(PUBLIC_KEY_PREFIX + keyId, publicKeyHex).apply()
  }

  fun readPublicKey(context: Context, keyId: String): String? =
    prefs(context).getString(PUBLIC_KEY_PREFIX + keyId, null)

  fun deletePublicKey(context: Context, keyId: String) {
    prefs(context).edit().remove(PUBLIC_KEY_PREFIX + keyId).apply()
  }

  fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

  fun hasKey(keyId: String): Boolean =
    runCatching { keyStore().containsAlias(alias(keyId)) }.getOrDefault(false)

  fun deleteKey(keyId: String) {
    runCatching { keyStore().deleteEntry(alias(keyId)) }
  }

  /**
   * Result of generating a wrapping key, including whether StrongBox actually
   * backed it — the caller cannot otherwise tell, and "probably hardware" is
   * not a useful thing to tell a wallet user.
   */
  data class GeneratedKey(val key: SecretKey, val strongBoxBacked: Boolean)

  fun generateKey(
    keyId: String,
    policy: String,
    invalidation: String
  ): GeneratedKey {
    val requiresAuth = policy != WalletKeystoreModule.POLICY_NONE

    fun build(strongBox: Boolean): SecretKey {
      val builder = KeyGenParameterSpec.Builder(
        alias(keyId),
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setUserAuthenticationRequired(requiresAuth)

      if (requiresAuth) {
        // Pinning the key to the current biometric enrollment destroys it when
        // the user adds or removes a fingerprint. That is the whole point of
        // the invalidation axis, and why it is never implied by the auth
        // policy: opting in silently would lose wallets.
        builder.setInvalidatedByBiometricEnrollment(
          invalidation == WalletKeystoreModule.INVALIDATION_ON_ENROLLMENT_CHANGE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          // 0 means "authenticate for every single use", which is what makes
          // the CryptoObject binding meaningful — a time window would let a
          // later operation ride on an earlier authentication.
          builder.setUserAuthenticationParameters(
            0,
            if (policy == WalletKeystoreModule.POLICY_BIOMETRIC_ONLY) {
              KeyProperties.AUTH_BIOMETRIC_STRONG
            } else {
              KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            }
          )
        } else {
          @Suppress("DEPRECATION")
          builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
      }

      if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setIsStrongBoxBacked(true)
      }

      val generator = KeyGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_AES,
        ANDROID_KEYSTORE
      )
      generator.init(builder.build())
      return generator.generateKey()
    }

    // StrongBox is absent on most devices and throws rather than degrading, so
    // the fallback is mandatory. Which one was used is reported back rather
    // than hidden.
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        GeneratedKey(build(strongBox = true), true)
      } catch (_: StrongBoxUnavailableException) {
        deleteKey(keyId)
        GeneratedKey(build(strongBox = false), false)
      }
    } else {
      GeneratedKey(build(strongBox = false), false)
    }
  }

  /**
   * Asked of the key rather than inferred from a policy string, which is not
   * recorded anywhere. Fails closed: unreadable metadata means prompt.
   */
  fun requiresAuth(key: SecretKey): Boolean = try {
    val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
    (factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo)
      .isUserAuthenticationRequired
  } catch (_: Exception) {
    true
  }

  /**
   * Keystore wraps "used without authentication" in an IllegalBlockSizeException
   * rather than throwing UserNotAuthenticatedException, so walk the cause chain.
   */
  fun isNotAuthenticated(t: Throwable): Boolean {
    var current: Throwable? = t
    while (current != null) {
      if (current is android.security.keystore.UserNotAuthenticatedException) return true
      if (current::class.java.name.endsWith("KeyStoreException") &&
        current.message?.contains("not authenticated", ignoreCase = true) == true
      ) {
        return true
      }
      current = current.cause
    }
    return false
  }

  fun loadKey(keyId: String): SecretKey? =
    keyStore().getKey(alias(keyId), null) as? SecretKey

  fun encryptCipher(key: SecretKey): Cipher =
    Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }

  fun decryptCipher(key: SecretKey, iv: ByteArray): Cipher =
    Cipher.getInstance(TRANSFORMATION).apply {
      init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
    }

  fun authenticatorsFor(policy: String): Int =
    if (policy == WalletKeystoreModule.POLICY_BIOMETRIC_ONLY) {
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    }

  /**
   * A key pinned to a biometric enrollment that has since changed throws on
   * init, and the secret it wrapped is gone for good. Distinguished from a
   * transient failure so callers can start recovery instead of retrying.
   */
  fun isInvalidated(t: Throwable): Boolean =
    t is KeyPermanentlyInvalidatedException

  fun hex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

  fun fromHex(hex: String): ByteArray? {
    if (hex.length % 2 != 0 || hex.isEmpty()) return null
    return try {
      ByteArray(hex.length / 2) {
        hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
      }
    } catch (_: NumberFormatException) {
      null
    }
  }
}
