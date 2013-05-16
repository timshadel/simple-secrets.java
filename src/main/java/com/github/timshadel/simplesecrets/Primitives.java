package com.github.timshadel.simplesecrets;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;


public class Primitives
{
  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KEY_ALGORITHM = "AES";


  /**
   * Provide 16 securely random bytes.
   *
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
   * <p/>
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
   * <p/>
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
   * <p/>
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
   * <p/>
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
   * <p/>
   * Uses AES256 with a random 128-bit initialization vector.
   *
   * @param binary     - the plaintext binary string
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

    byte[] iv_bytes = cipher.getIV();
    byte[] binary_bytes = cipher.update(binary);
    byte[] final_bytes = cipher.doFinal();

    byte[] encrypted = joinByteArrays(iv_bytes, binary_bytes, final_bytes);
    return encrypted;
  }


  /**
   * Decrypt buffer with the given key and initialization vector.
   * <p/>
   * Uses AES256.
   *
   * @param binary     - ciphertext
   * @param master_key - the 256-bit encryption key
   * @param iv         - the 128-bit initialization vector
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

    byte[] binary_bytes = cipher.update(binary);
    byte[] final_bytes = cipher.doFinal();

    byte[] decrypted = joinByteArrays(binary_bytes, final_bytes);
    return decrypted;
  }


  /**
   * Generate an encryption or hmac key from the master key and role.
   * <p/>
   * Uses SHA256(key || role).
   *
   * @param master_key
   * @param role
   * @return
   * @throws GeneralSecurityException
   * @todo link or citation
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
   * <p/>
   * Throws IllegalArgumentException if not.
   *
   * @param binary
   * @throws IllegalArgumentException
   */
  private static void assertBinary(final byte[] binary)
  {
    if (binary == null)
      throw new IllegalArgumentException("Byte array required.");
  }


  /**
   * Asserts that the given byte array is non-null and of the given size.
   * <p/>
   * Throws IllegalArgumentException if not.
   *
   * @param binary
   * @param bytes
   * @throws IllegalArgumentException
   */
  private static void assertBinarySize(final byte[] binary, int bytes)
  {
    if (binary == null || binary.length != bytes)
      throw new IllegalArgumentException((bytes * 8) + "-bit byte array required.");
  }


  private static byte[] joinByteArrays(final byte[]... binaries)
  {
    int size = 0;
    if (binaries[0] == null)
      return new byte[0];

    for (byte[] binary : binaries) {
      size += binary.length;
    }

    int index = 0;
    byte[] result = new byte[size];
    for (byte[] binary : binaries) {
      System.arraycopy(binary, 0, result, index, binary.length);
      index += binary.length;
    }

    return result;
  }
}