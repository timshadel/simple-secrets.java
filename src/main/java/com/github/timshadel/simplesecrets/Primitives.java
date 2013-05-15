package com.github.timshadel.simplesecrets;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Primitives
{
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