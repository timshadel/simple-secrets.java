package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;


@RunWith(PowerMockRunner.class)
public class PrimitivesTest
{
  private static final byte[] DATA = hexStringToBytes("11", 25);
  private static final byte[] KEY = hexStringToBytes("cd", 32);
  private static final byte[] IV = hexStringToBytes("ab", 16);


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


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_null_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_hmac(null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_master_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_hmac(hexStringToBytes("bc", 31));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_hmac_master_key_too_long()
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


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_key_null_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_key(null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_key_master_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_key(hexStringToBytes("33", 31));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_sender_key_master_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.derive_sender_key(hexStringToBytes("33", 33));
  }


  @Test
  public void test_derive_sender_key()
          throws GeneralSecurityException
  {
    byte[] master_key = hexStringToBytes("bc", 32);
    byte[] expected = hexStringToBytes("327b5f32d7ff0beeb0a7224166186e5f1fc2ba681092214a25b1465d1f17d837");

    byte[] result = Primitives.derive_sender_key(master_key);
    assertTrue("Derives sender key", Arrays.equals(expected, result));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_hmac_null_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_hmac(null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_hmac_master_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_hmac(hexStringToBytes("bc", 31));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_hmac_master_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_hmac(hexStringToBytes("bc", 33));
  }


  @Test
  public void test_derive_receiver_hmac()
          throws GeneralSecurityException
  {
    byte[] master_key = hexStringToBytes("bc", 32);
    byte[] expected = hexStringToBytes("375f52dff2a263f2d0e0df11d252d25ba18b2f9abae1f0cbf299bab8d8c4904d");

    byte[] result = Primitives.derive_receiver_hmac(master_key);
    assertTrue("Derives receiver HMAC key", Arrays.equals(expected, result));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_key_null_master_key()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_key(null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_key_master_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_key(hexStringToBytes("33", 31));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_derive_receiver_key_master_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.derive_receiver_key(hexStringToBytes("33", 33));
  }


  @Test
  public void test_derive_receiver_key()
          throws GeneralSecurityException
  {
    byte[] master_key = hexStringToBytes("bc", 32);
    byte[] expected = hexStringToBytes("c7e2a9660369f243aed71b0de0c49ee69719d20261778fdf39991a456566ef22");

    byte[] result = Primitives.derive_receiver_key(master_key);
    assertTrue("Derives receiver key", Arrays.equals(expected, result));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_encrypt_null_binary()
          throws GeneralSecurityException
  {
    Primitives.encrypt(null, KEY);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_encrypt_null_key()
          throws GeneralSecurityException
  {
    Primitives.encrypt(hexStringToBytes("11", 25), null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_encrypt_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.encrypt(hexStringToBytes("11", 25), hexStringToBytes("cd", 31));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_encrypt_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.encrypt(hexStringToBytes("11", 25), hexStringToBytes("cd", 33));
  }


  @Test
  public void test_encrypt()
          throws GeneralSecurityException
  {
    byte[] result = Primitives.encrypt(DATA, KEY);
    assertEquals(48, result.length);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_null_binary()
          throws GeneralSecurityException
  {
    Primitives.decrypt(null, KEY, IV);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_null_key()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, null, IV);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, hexStringToBytes("cd", 31), IV);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, hexStringToBytes("cd", 33), IV);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_null_iv()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, KEY, null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_iv_too_short()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, KEY, hexStringToBytes("ab", 15));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_decrypt_iv_too_long()
          throws GeneralSecurityException
  {
    Primitives.decrypt(DATA, KEY, hexStringToBytes("ab", 17));
  }


  @Test
  public void test_decrypt()
          throws GeneralSecurityException
  {
    byte[] ciphertext = hexStringToBytes("f8c6db482b00b25b122e2dc8c50c52db8dbd58a796fcaed6d926e87bb227dfbb");
    byte[] iv = hexStringToBytes("3f05e3a3fb9cdb198f498174002965ac");

    byte[] plaintext = Primitives.decrypt(ciphertext, KEY, iv);
    assertTrue("Decrypts the data", Arrays.equals(DATA, plaintext));
  }


  @Test
  public void test_encrypt_and_decrypt()
          throws GeneralSecurityException
  {
    byte[] encrypted = Primitives.encrypt(DATA, KEY);

    byte[] iv = Arrays.copyOfRange(encrypted, 0, 16);
    byte[] ciphertext = Arrays.copyOfRange(encrypted, 16, encrypted.length);
    byte[] plaintext = Primitives.decrypt(ciphertext, KEY, iv);

    assertTrue("Encrypts and decrypts the data", Arrays.equals(DATA, plaintext));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_identify_null_binary()
          throws GeneralSecurityException
  {
    Primitives.identify(null);
  }


  @Test
  public void test_identify()
          throws GeneralSecurityException
  {
    byte[] identity = Primitives.identify(KEY);
    assertTrue(Arrays.equals(hexStringToBytes("b097da5683f1"),identity));
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_mac_null_binary()
          throws GeneralSecurityException
  {
    Primitives.hmac(null, KEY);
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_mac_null_hmac_key()
          throws GeneralSecurityException
  {
    Primitives.hmac(DATA, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_mac_hmac_key_too_short()
          throws GeneralSecurityException
  {
    Primitives.hmac(DATA, hexStringToBytes("9f", 31));
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_mac_hmac_key_too_long()
          throws GeneralSecurityException
  {
    Primitives.hmac(DATA, hexStringToBytes("9f", 33));
  }

  @Test
  public void test_mac()
          throws GeneralSecurityException
  {
    byte[] expected = hexStringToBytes("adf1793fdef44c54a2c01513c0c7e4e71411600410edbde61558db12d0a01c65");
    assertTrue(Arrays.equals(expected, Primitives.hmac(DATA, hexStringToBytes("9f", 32))));
  }


  // Private method tests


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinary_null()
          throws Exception
  {
    Whitebox.invokeMethod(Primitives.class, "assertBinary", (byte[]) null);
  }


  @Test
  public void test_assertBinary()
          throws Exception
  {
    Whitebox.invokeMethod(Primitives.class, "assertBinary", new byte[16]);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinarySize_null_binary()
          throws Exception
  {
    Whitebox.invokeMethod(Primitives.class, "assertBinarySize", (byte[]) null, 1);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinarySize_invalid_size()
          throws Exception
  {
    Whitebox.invokeMethod(Primitives.class, "assertBinarySize", new byte[16], 1);
  }


  @Test
  public void test_assertBinarySize()
          throws Exception
  {
    Whitebox.invokeMethod(Primitives.class, "assertBinarySize", new byte[16], 16);
  }


  @Test
  public void test_joinByteArrays_null()
          throws Exception
  {
    byte[] result = Whitebox.invokeMethod(Primitives.class, "joinByteArrays", (byte[]) null);
    assertNotNull(result);
    assertEquals(0, result.length);
  }


  @Test
  public void test_joinByteArrays()
          throws Exception
  {
    byte[] array1 = "123".getBytes();
    byte[] array2 = "456".getBytes();
    byte[] array3 = "789".getBytes();
    byte[] array4 = "0".getBytes();
    byte[] result = Whitebox.invokeMethod(Primitives.class, "joinByteArrays", array1, array2, array3, array4);
    assertNotNull(result);
    assertEquals(10, result.length);
    assertTrue(Arrays.equals("1234567890".getBytes(), result));
  }


  // Helper methods


  private static final byte[] hexStringToBytes(String string)
  {
    return hexStringToBytes(string, 1);
  }


  private static final byte[] hexStringToBytes(String string, int repeat)
  {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < repeat; i++)
      builder.append(string);
    try {
      return new Hex().decode(builder.toString().getBytes());
    }
    catch (DecoderException e) {
      e.printStackTrace();
      return null;
    }
  }
}