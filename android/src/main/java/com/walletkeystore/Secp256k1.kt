package com.walletkeystore

import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9IntegerConverter
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom

/**
 * secp256k1 signing with Ethereum's conventions. libsecp256k1 gives iOS the
 * recovery id directly; BouncyCastle does not, so it is derived here. The
 * known-answer vectors are what keep the two from diverging.
 */
internal object Secp256k1 {

  private val CURVE_PARAMS: X9ECParameters = CustomNamedCurves.getByName("secp256k1")
  private val CURVE = ECDomainParameters(
    CURVE_PARAMS.curve,
    CURVE_PARAMS.g,
    CURVE_PARAMS.n,
    CURVE_PARAMS.h
  )
  private val HALF_CURVE_ORDER: BigInteger = CURVE_PARAMS.n.shiftRight(1)

  /** Valid private keys are [1, n-1]. */
  fun isValidPrivateKey(d: BigInteger): Boolean =
    d.signum() > 0 && d < CURVE.n

  fun generatePrivateKey(): ByteArray {
    val random = SecureRandom()
    val bytes = ByteArray(32)
    // Rejection sampling rather than reduction mod n: reducing would bias the
    // distribution toward small keys. The retry probability is ~2^-128.
    while (true) {
      random.nextBytes(bytes)
      val candidate = BigInteger(1, bytes)
      if (isValidPrivateKey(candidate)) return bytes
    }
  }

  /** Uncompressed SEC1 encoding: 0x04 || X || Y, 65 bytes. */
  fun publicKeyFrom(privateKey: ByteArray): ByteArray {
    val d = BigInteger(1, privateKey)
    require(isValidPrivateKey(d)) { "private key out of range" }
    return CURVE.g.multiply(d).normalize().getEncoded(false)
  }

  /**
   * Signs a 32-byte digest into 65 bytes: r || s || v, with v in 27/28.
   *
   * RFC 6979 nonces come from HMacDSAKCalculator. A nonce that repeats across
   * two signatures reveals the private key, so never hand-roll this.
   */
  fun sign(digest: ByteArray, privateKey: ByteArray): ByteArray {
    require(digest.size == 32) { "digest must be 32 bytes" }

    val d = BigInteger(1, privateKey)
    require(isValidPrivateKey(d)) { "private key out of range" }

    val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
    signer.init(true, ECPrivateKeyParameters(d, CURVE))
    val components = signer.generateSignature(digest)

    val r = components[0]
    // EIP-2: only the low-s form is canonical. (r, s) and (r, n-s) are both
    // valid ECDSA, but Ethereum rejects the high one, so roughly half of all
    // signatures would fail on-chain without this.
    val s = if (components[1] > HALF_CURVE_ORDER) CURVE.n.subtract(components[1])
    else components[1]

    val publicKey = CURVE.g.multiply(d).normalize()
    val recId = recoveryId(r, s, digest, publicKey)
    require(recId >= 0) { "could not determine recovery id" }

    return toBytes32(r) + toBytes32(s) + byteArrayOf((recId + 27).toByte())
  }

  /**
   * Finds which candidate public key recoverable from (r, s) is ours, by trying
   * each and comparing — libsecp256k1 gets this free from signing, BC does not.
   */
  private fun recoveryId(
    r: BigInteger,
    s: BigInteger,
    digest: ByteArray,
    expected: ECPoint
  ): Int {
    for (recId in 0..3) {
      val candidate = recoverPublicKey(recId, r, s, digest) ?: continue
      if (candidate.equals(expected)) return recId
    }
    return -1
  }

  private fun recoverPublicKey(
    recId: Int,
    r: BigInteger,
    s: BigInteger,
    digest: ByteArray
  ): ECPoint? {
    val n = CURVE.n

    // recId's high bit selects which multiple of n was subtracted from x when
    // r was reduced; its low bit selects the sign of y.
    val i = BigInteger.valueOf(recId.toLong() / 2)
    val x = r.add(i.multiply(n))

    val prime = CURVE_PARAMS.curve.field.characteristic
    if (x >= prime) return null

    val R = decompressKey(x, (recId and 1) == 1) ?: return null
    // A valid R must be n-torsion; if nR is not the point at infinity this
    // candidate is spurious.
    if (!R.multiply(n).isInfinity) return null

    val e = BigInteger(1, digest)
    val eInv = BigInteger.ZERO.subtract(e).mod(n)
    val rInv = r.modInverse(n)
    val srInv = rInv.multiply(s).mod(n)
    val eInvrInv = rInv.multiply(eInv).mod(n)

    return ECAlgorithms.sumOfTwoMultiplies(CURVE.g, eInvrInv, R, srInv).normalize()
  }

  private fun decompressKey(xBN: BigInteger, yBit: Boolean): ECPoint? {
    val converter = X9IntegerConverter()
    val compEnc = converter.integerToBytes(
      xBN,
      1 + converter.getByteLength(CURVE_PARAMS.curve)
    )
    compEnc[0] = if (yBit) 0x03 else 0x02
    return try {
      CURVE_PARAMS.curve.decodePoint(compEnc)
    } catch (_: IllegalArgumentException) {
      // x was not on the curve for this candidate.
      null
    }
  }

  /** Left-pads to exactly 32 bytes, dropping BigInteger's sign byte. */
  private fun toBytes32(value: BigInteger): ByteArray {
    val raw = value.toByteArray()
    val out = ByteArray(32)
    when {
      raw.size == 32 -> return raw
      raw.size > 32 -> System.arraycopy(raw, raw.size - 32, out, 0, 32)
      else -> System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
    }
    return out
  }
}
