package com.github.timshadel.simplesecrets;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Primitives
{
  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KEY_ALGORITHM = "AES";


  /**
   * Provide 16 securely random bytes.
   * @return
   */
  public static byte[] nonce()
  {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }


  /**
   * Generate the authentication key for messages originating from the channel's Sender side.
   *
   * Uses the ASCII string 'simple-crypto/sender-hmac-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_sender_hmac(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/sender-hmac-key");
  }


  /**
   * Generate the encryption key for messages originating from the channel's Sender side.
   *
   * Uses the ASCII string 'simple-crypto/sender-cipher-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_sender_key(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/sender-cipher-key");
  }


  /**
   * Generate the authentication key for messages originating from the channel's Receiver side.
   *
   * Uses the ASCII string 'simple-crypto/receiver-hmac-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_receiver_hmac(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/receiver-hmac-key");
  }


  /**
   * Generate the encryption key for messages originating from the channel's Receiver side.
   *
   * Uses the ASCII string 'simple-crypto/receiver-cipher-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_receiver_key(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/receiver-cipher-key");
  }


  /**
   * Encrypt buffer with the given key.
   *
   * Uses AES256 with a random 128-bit initialization vector.
   *
   * @param binary - the plaintext binary string
   * @param master_key - the 256-bit encryption key
   * @return - a binary string of (IV + ciphertext)
   * @throws GeneralSecurityException
   */
  public static byte[] encrypt(final byte[] binary, final byte[] master_key)
          throws GeneralSecurityException
  {
    assertBinary(binary);
    assertBinarySize(master_key, 32);

    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    SecretKeySpec keySpec = new SecretKeySpec(master_key, KEY_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);

    ByteArrayOutputStream out = new ByteArrayOutputStream(48);

    byte[] encrypted = null;
    try
    {
      out.write(cipher.getIV());
      out.write(cipher.update(binary));
      out.write(cipher.doFinal());

      encrypted = out.toByteArray();
      out.close();
    }
    catch(IOException e)
    {
      e.printStackTrace();
    }
    finally
    {
      try{ out.close(); } catch(IOException e){ e.printStackTrace(); }
    }

    return encrypted;
  }


  /**
   * Decrypt buffer with the given key and initialization vector.
   *
   * Uses AES256.
   *
   * @param binary - ciphertext
   * @param master_key - the 256-bit encryption key
   * @param iv - the 128-bit initialization vector
   * @return - plaintext binary string
   * @throws GeneralSecurityException
   */
  public static byte[] decrypt(final byte[] binary, final byte[] master_key, final byte[] iv)
          throws GeneralSecurityException
  {
    assertBinary(binary);
    assertBinarySize(master_key, 32);
    assertBinarySize(iv, 16);

    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    SecretKeySpec keySpec = new SecretKeySpec(master_key, KEY_ALGORITHM);
    IvParameterSpec ivSpec = new IvParameterSpec(iv, 0, cipher.getBlockSize());
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    ByteArrayOutputStream out = new ByteArrayOutputStream(48);

    byte[] decrypted = null;
    try
    {
      out.write(cipher.update(binary));
      out.write(cipher.doFinal());

      decrypted = out.toByteArray();
      out.close();
    }
    catch(IOException e)
    {
      e.printStackTrace();
    }
    finally
    {
      try{ out.close(); } catch(IOException e){ e.printStackTrace(); }
    }

    return decrypted;
  }


  /**
   * Generate an encryption or hmac key from the master key and role.
   *
   * Uses SHA256(key || role).
   *
   * @todo link or citation
   * @param master_key
   * @param role
   * @return
   * @throws GeneralSecurityException
   */
  private static byte[] derive(final byte[] master_key, final String role)
          throws GeneralSecurityException
  {
    assertBinarySize(master_key, 32);

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(master_key);
    digest.update(role.getBytes());
    return digest.digest();
  }


  /**
   * Asserts that the given byte array is non-null.
   *
   * Throws IllegalArgumentException if not.
   *
   * @throws IllegalArgumentException
   * @param binary
   */
  private static void assertBinary(final byte[] binary)
  {
    if(binary == null)
      throw new IllegalArgumentException("Byte array required.");
  }


  /**
   * Asserts that the given byte array is non-null and of the given size.
   *
   * Throws IllegalArgumentException if not.
   *
   * @throws IllegalArgumentException
   * @param binary
   * @param bytes
   */
  private static void assertBinarySize(final byte[] binary, int bytes)
  {
    if(binary == null || binary.length != bytes)
      throw new IllegalArgumentException((bytes * 8) + "-bit byte array required.");
  }
}