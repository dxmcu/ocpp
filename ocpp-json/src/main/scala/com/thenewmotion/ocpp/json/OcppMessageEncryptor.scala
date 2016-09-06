package com.thenewmotion.ocpp.json

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.digest.DigestUtils
import org.slf4j.LoggerFactory

object OcppMessageEncryptor {
  // encryption
  private final val BlockAlgorithm = "AES"
  private final val BlockMethod = "AES/CBC/NoPadding"
  private final val BlockCipher = Cipher.getInstance(BlockMethod)
  private final val RandomBytes = new SecureRandom()
  private final val SharedKey = "eNovates00000000"

  // hashing
  private final val HashAlgorithm = "HmacSHA1"
  private final val KeyedHash = Mac.getInstance(HashAlgorithm)
}

class OcppMessageEncryptor(val serial: String) {

  import OcppMessageEncryptor._

  private[this] val logger = LoggerFactory.getLogger(OcppMessageEncryptor.this.getClass)

  KeyedHash.init(new SecretKeySpec(serialToEncryptKey, HashAlgorithm))

  private def logBytes(name: String, bytes: Array[Byte]) = {
    logger.info(s"\n$name: ${bytes.map(_.toInt).mkString(",")}")
  }

  private lazy val serialToEncryptKey: Array[Byte] = {
    val textKey: Array[Byte] = (SharedKey + serial).getBytes
    logBytes("textKey", textKey)
    val encryptKey = DigestUtils.sha1Hex(textKey).getBytes
      .padTo(BlockCipher.getBlockSize, 0.toByte)
      .take(BlockCipher.getBlockSize)
    logBytes("encryptKey", encryptKey)
    encryptKey
  }

  private def addHash(msg: Array[Byte]): Array[Byte] = {
    val hash = KeyedHash.doFinal(msg)
    logBytes("hash", hash)
    val addedHash = hash ++ msg
    logBytes("message", addedHash)
    addedHash
  }

  private def removeHash(msg: Array[Byte]): Array[Byte] = {
    val (hash, message) = msg.splitAt(KeyedHash.getMacLength)
    logBytes("hash", hash)
    logBytes("message", message)
    if (!addHash(message).take(KeyedHash.getMacLength).sameElements(hash)) {
      throw new IllegalArgumentException("Invalid hash")
    }
    message
  }

  private def encryptBytes(msg: Array[Byte]): Array[Byte] = {
    BlockCipher.init(
      Cipher.ENCRYPT_MODE,
      new SecretKeySpec(serialToEncryptKey, BlockAlgorithm)
    )

    val remainder = msg.length % 16
    val padding =
      if (remainder == 0) 0
      else 16 - remainder

    logger.info(s"\npadding: $padding")

    val encrypted = BlockCipher.doFinal(
      msg.padTo(msg.length + padding, ' '.toByte))
    logBytes("encrypted", encrypted)
    encrypted
  }

  private def decryptBytes(msg: Array[Byte]): Array[Byte] = {
    BlockCipher.init(
      Cipher.DECRYPT_MODE,
      new SecretKeySpec(serialToEncryptKey, BlockAlgorithm),
      new IvParameterSpec(new Array[Byte](BlockCipher.getBlockSize))
      // The supplied IV could be anything. decrypt simply drops
      // the first "corrupted" block the message which serves as
      // the IV for subsequent message blocks
    )

    val decrypted = BlockCipher.doFinal(msg)
      .reverse.dropWhile(_ == ' '.toByte).reverse
    logBytes("decrypted", decrypted)
    decrypted
  }

  def encrypt(msg: String): Array[Byte] = {
    val IvBytes = new Array[Byte](BlockCipher.getBlockSize)
    RandomBytes.nextBytes(IvBytes)
    val encrypting: Array[Byte] = IvBytes ++ msg.getBytes("UTF8")
    logBytes("encrypting", encrypting)
    addHash(encryptBytes(encrypting))
  }

  def decrypt(msg: Array[Byte]): String = {
    logBytes("decrypting", msg)
    decryptBytes(removeHash(msg))
      .drop(BlockCipher.getBlockSize)
      .map(_.toChar).mkString
  }
}
