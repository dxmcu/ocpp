package com.thenewmotion.ocpp.json

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.digest.DigestUtils
import org.slf4j.LoggerFactory

object OcppMessageAesEncryptor {
  // encryption
  private final val BlockAlgorithm = "AES"
  private final val BlockMethod = "AES/CBC/NoPadding" // we do our own padding (saving bytes)
  private final val BlockCipher = Cipher.getInstance(BlockMethod)
  private final val RandomBytes = new SecureRandom()
  private final val SharedKey = "eNovates00000000"

  // hashing
  private final val HashAlgorithm = "HmacSHA1"
  private final val KeyedHash = Mac.getInstance(HashAlgorithm)
}

// TODO: implement the suggestions in TNM-3236
class OcppMessageAesEncryptor(val serial: String) {

  import OcppMessageAesEncryptor._

  private[this] val logger = LoggerFactory.getLogger(OcppMessageAesEncryptor.this.getClass)

  KeyedHash.init(new SecretKeySpec(serialToEncryptKey, HashAlgorithm))

  private def logBytes(name: String, bytes: Array[Byte]) = {
    logger.debug(s"\n$name: ${bytes.map(_.toInt).mkString(",")}")
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

  private def encryptBytes(msg: Array[Byte]): Array[Byte] = {
    BlockCipher.init(
      Cipher.ENCRYPT_MODE,
      new SecretKeySpec(serialToEncryptKey, BlockAlgorithm)
    )

    val remainder = msg.length % 16
    val padding =
      if (remainder == 0) 0
      else 16 - remainder

    logger.debug(s"\npadding: $padding")

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

  private def addHash(msg: Array[Byte]): Array[Byte] = {
    val hash = KeyedHash.doFinal(msg)
    logBytes("addHash -> hash", hash)
    val addedHash = hash ++ msg
    addedHash
  }

  def encrypt(msg: String): Array[Byte] = {
    val IvBytes = new Array[Byte](BlockCipher.getBlockSize)
    RandomBytes.nextBytes(IvBytes)
    val data: Array[Byte] = IvBytes ++ msg.getBytes("UTF8")
    logBytes("encrypt -> data", data)
    addHash(encryptBytes(data))
  }

  def decrypt(msg: Array[Byte]): String = {
    val (hash, data) = msg.splitAt(KeyedHash.getMacLength)
    logBytes("decrypt -> hash", hash)
    logBytes("decrypt -> data", data)
    if (!addHash(data).take(KeyedHash.getMacLength).sameElements(hash)) {
      throw new IllegalArgumentException("decrypt: authentication error")
    }

    decryptBytes(data)
      .drop(BlockCipher.getBlockSize)
      .map(_.toChar).mkString
  }
}
