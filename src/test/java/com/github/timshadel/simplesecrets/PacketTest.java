package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;


@RunWith(PowerMockRunner.class)
public class PacketTest
{
  private static final String MASTER_KEY = hexString("cd", 32);
  private static final String DATA = "This is a secret message!";


  @Test(expected = IllegalArgumentException.class)
  public void test_constrcutor_null_key()
  {
    new Packet(null);
  }


  @Test
  public void test_constrcutor()
  {
    Object object = new Packet(MASTER_KEY);
  }


  // Helper methods


  private static final byte[] hexStringToBytes(String string)
  {
    return hexStringToBytes(string, 1);
  }


  private static final byte[] hexStringToBytes(String string, int repeat)
  {
    try {
      return new Hex().decode(hexString(string,repeat).getBytes());
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
