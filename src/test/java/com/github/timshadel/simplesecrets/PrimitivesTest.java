package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;

public class PrimitivesTest
{
  @Test
  public void constructor()
  {
    Object object = new Primitives();
    assertNotNull(object);
  }


  @Test
  public void test_nonce()
  {
    byte[] nonce = Primitives.nonce();
    assertEquals("Nonce is 16 bytes", 16, nonce.length);

    byte[] another_nonce = Primitives.nonce();
    assertFalse("Nonce is not repeated", Arrays.equals(nonce, another_nonce));
  }

  @Test( expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_null_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_hmac(null);
  }

  @Test( expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_too_short_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_hmac(hexStringToBytes("bc", 31));
  }

  @Test( expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_too_long_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_hmac(hexStringToBytes("bc", 33));
  }

  @Test
  public void test_derive_sender_hmac()
    throws GeneralSecurityException
  {
    byte[] master_key = hexStringToBytes("bc", 32);
    byte[] expected = hexStringToBytes("1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088");

    byte[] result = Primitives.derive_sender_hmac(master_key);
    assertTrue("Derives sender HMAC key", Arrays.equals(expected, result));
  }


  private static final byte[] hexStringToBytes(String string)
  {
    return hexStringToBytes(string, 1);
  }


  private static final byte[] hexStringToBytes(String string, int repeat)
  {
    StringBuilder builder = new StringBuilder();
    for(int i = 0; i < repeat; i++)
      builder.append(string);
    try {
      return new Hex().decode(builder.toString().getBytes());
    } catch (DecoderException e) {
      e.printStackTrace();
      return null;
    }
  }
}