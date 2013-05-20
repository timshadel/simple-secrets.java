package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.security.GeneralSecurityException;


public class Packet
{
  private final byte[] master_key;
  private final byte[] identity;


  public Packet(String master_key)
          throws GeneralSecurityException
  {
    if (master_key == null)
      throw new IllegalArgumentException("Master key is required.");

    try {
      this.master_key = Hex.decodeHex(master_key.toCharArray());
    }
    catch (DecoderException e) {
      throw new IllegalArgumentException("Invalid hexidecimal key.", e);
    }

    identity = Primitives.identify(this.master_key);
  }


  public byte[] build_body(Object data)
          throws IOException
  {
    byte[] nonce = Primitives.nonce();
    byte[] binary = Primitives.serialize(data);

    byte[] body = Utilities.joinByteArrays(nonce, binary);

    Primitives.zero(nonce, binary);
    return body;
  }
}
