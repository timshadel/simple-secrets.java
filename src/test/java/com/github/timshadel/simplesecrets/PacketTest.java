package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.internal.util.reflection.Whitebox;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;


@RunWith(PowerMockRunner.class)
public class PacketTest
{
  private static final String MASTER_KEY = hexString("cd", 32);
  private static final String DATA = "This is a secret message!";


  @Test(expected = IllegalArgumentException.class)
  public void test_constructor_null_key()
          throws GeneralSecurityException
  {
    new Packet(null);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_constructor_bad_key()
          throws GeneralSecurityException
  {
    new Packet("I'm not a hex string.");
  }


  @Test
  public void test_constructor()
          throws GeneralSecurityException
  {
    Object packet = new Packet(MASTER_KEY);
    assertNotNull(packet);
    assertTrue(Arrays.equals(hexStringToBytes(MASTER_KEY), (byte[])Whitebox.getInternalState(packet, "master_key")));
    assertTrue(Arrays.equals(hexStringToBytes("b097da5683f1"), (byte[]) Whitebox.getInternalState(packet, "identity")));
  }


  @Test
  public void test_build_body()
          throws GeneralSecurityException, IOException
  {
    byte[] body = new Packet(MASTER_KEY).build_body("abcd");

    // First 16 bytes will be unpredictable nonce.
    // Remaining bytes will be a serialization of the object.
    assertEquals(21, body.length);

    byte[] expected = new byte[]{ -92, 97, 98, 99, 100 };
    assertTrue(Arrays.equals(expected, Arrays.copyOfRange(body, 16, body.length)));
  }


  @Test(expected = GeneralSecurityException.class)
  public void test_body_to_data_too_short()
          throws GeneralSecurityException, IOException
  {
    byte[] body = new byte[15];
    new Packet(MASTER_KEY).body_to_data(body, String.class);
  }

  @Test
  public void test_body_to_data()
          throws GeneralSecurityException, IOException
  {
    byte[] nonce = Primitives.nonce();
    byte[] data = new byte[]{ -92, 97, 98, 99, 100 };

    byte[] body = Utilities.joinByteArrays(nonce, data);

    assertEquals("abcd", new Packet(MASTER_KEY).body_to_data(body, String.class));
  }


  // Helper methods


  private static final byte[] hexStringToBytes(String string)
  {
    return hexStringToBytes(string, 1);
  }


  private static final byte[] hexStringToBytes(String string, int repeat)
  {
    try {
      return new Hex().decode(hexString(string, repeat).getBytes());
    }
    catch (DecoderException e) {
      e.printStackTrace();
      return null;
    }
  }


  private static final String hexString(String string, int repeat)
  {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < repeat; i++)
      builder.append(string);
    return builder.toString();
  }
}
