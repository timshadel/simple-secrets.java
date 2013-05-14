package com.github.timshadel.simplesecrets;

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
}