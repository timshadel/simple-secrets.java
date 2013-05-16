package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;


public class Packet
{
  private final byte[] master_key;


  public Packet(String master_key)
  {
    if (master_key == null)
      throw new IllegalArgumentException("Master key is required.");

    try {
      this.master_key = Hex.decodeHex(master_key.toCharArray());
    }
    catch (DecoderException e) {
      throw new IllegalArgumentException("Invalid hexidecimal key.", e);
    }
  }
}
