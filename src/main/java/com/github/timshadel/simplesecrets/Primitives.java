package com.github.timshadel.simplesecrets;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Primitives
{
  private byte key;

  public Primitives(byte key)
  {
    this.key = key;
  }


  public static byte[] nonce()
  {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }


  public static byte[] derive_sender_hmac(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/sender-hmac-key");
  }


  private static byte[] derive(final byte[] master_key, final String role)
          throws GeneralSecurityException
  {
    assertBinarySize(master_key, 32);

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(master_key);
    digest.update(role.getBytes());
    return digest.digest();
  }


  private static void assertBinarySize(final byte[] binary, int bytes)
  {
    if(binary == null || binary.length != bytes)
      throw new IllegalArgumentException((bytes * 8) + "-bit byte array required.");
  }
}