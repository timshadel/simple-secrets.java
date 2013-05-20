package com.github.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;


public class Packet
{
  private final byte[] master_key;
  private final byte[] identity;


  public Packet(String master_key)
          throws GeneralSecurityException
  {
    if (master_key == null)
      throw new IllegalArgumentException("Master key is required.");

    try
    {
      this.master_key = Hex.decodeHex(master_key.toCharArray());
    }
    catch (DecoderException e)
    {
      throw new IllegalArgumentException("Invalid hexidecimal key.", e);
    }

    identity = Primitives.identify(this.master_key);
  }


  public String pack(Object data)
          throws GeneralSecurityException, IOException
  {
    byte[] body = null;
    byte[] encrypted = null;
    byte[] packet = null;
    try
    {
      body = build_body(data);
      encrypted = encrypt_body(body, master_key);
      packet = authenticate(encrypted, master_key, identity);

      return Primitives.stringify(packet);
    }
    finally
    {
      Primitives.zero(body, encrypted, packet);
    }
  }


  public <T> T unpack(String packed_data, Class<T> klass)
          throws GeneralSecurityException, IOException
  {
    byte[] packet = null;
    byte[] cipher_data = null;
    byte[] body = null;
    try
    {
      packet = Primitives.binify(packed_data);
      cipher_data = verify(packet, master_key, identity);

      body = decrypt_body(cipher_data, master_key);

      return body_to_data(body, klass);
    }
    finally
    {
      Primitives.zero(packet, body, cipher_data);
    }
  }


  public static byte[] build_body(Object data)
          throws IOException
  {
    byte[] nonce = null;
    byte[] binary = null;
    try
    {
      nonce = Primitives.nonce();
      binary = Primitives.serialize(data);

      return Utilities.joinByteArrays(nonce, binary);
    }
    finally
    {
      Primitives.zero(nonce, binary);
    }
  }


  public static <T> T body_to_data(final byte[] body, final Class<T> klass)
          throws GeneralSecurityException, IOException
  {
    // Must at least have a nonce
    if(body.length < 16)
      throw new GeneralSecurityException("Invalid serialized payload.");

    byte[] nonce = null;
    byte[] payload = null;
    try
    {
      nonce = Arrays.copyOfRange(body, 0, 16);
      payload = Arrays.copyOfRange(body, 16, body.length);

      return Primitives.deserialize(payload, klass);
    }
    finally
    {
      Primitives.zero(nonce, payload);
    }
  }


  public static byte[] encrypt_body(final byte[] body, final byte[] master_key)
          throws GeneralSecurityException
  {
    byte[] key = null;
    try
    {
      key = Primitives.derive_sender_key(master_key);

      return Primitives.encrypt(body, key);
    }
    finally
    {
      Primitives.zero(key);
    }
  }


  public static byte[] decrypt_body(final byte[] cipher_data, final byte[] master_key)
          throws GeneralSecurityException
  {
    // Must at least have an iv
    if(cipher_data.length < 16)
      throw new GeneralSecurityException("Invalid encrypted payload.");

    byte[] iv = null;
    byte[] encrypted = null;
    byte[] key = null;
    try
    {
      iv = Arrays.copyOfRange(cipher_data, 0, 16);
      encrypted = Arrays.copyOfRange(cipher_data, 16, cipher_data.length);
      key = Primitives.derive_sender_key(master_key);

      return Primitives.decrypt(encrypted, key, iv);
    }
    finally
    {
      Primitives.zero(key, iv, encrypted);
    }
  }


  public static byte[] authenticate(final byte[] data, final byte[] master_key, final byte[] identity)
          throws GeneralSecurityException
  {
    byte[] hmac_key = null;
    byte[] mac = null;
    try
    {
      hmac_key = Primitives.derive_sender_hmac(master_key);

      byte[] auth = Utilities.joinByteArrays(identity, data);
      mac = Primitives.mac(auth, hmac_key);
      return Utilities.joinByteArrays(auth, mac);
    }
    finally
    {
      Primitives.zero(hmac_key, mac);
    }
  }


  public static byte[] verify(final byte[] packet, final byte[] master_key, final byte[] identity)
          throws GeneralSecurityException
  {
    // Must at least have an identity
    if(packet.length < 6)
      throw new GeneralSecurityException("Missing packet identity.");

    byte[] packet_id = Arrays.copyOfRange(packet, 0, 6);
    if(Primitives.compare(packet_id, identity) == false)
      throw new GeneralSecurityException("Invalid packet identity.");

    if(packet.length < 6 + 32)
      throw new GeneralSecurityException("Missing packet MAC.");

    byte[] data = Arrays.copyOfRange(packet, 0, packet.length - 32);
    byte[] packet_mac = Arrays.copyOfRange(packet, packet.length -32, packet.length);

    byte[] hmac_key = Primitives.derive_sender_hmac(master_key);
    byte[] mac = Primitives.mac(data, hmac_key);
    if(Primitives.compare(packet_mac, mac) == false)
      throw new GeneralSecurityException("Invalid packet MAC.");

    Primitives.zero(hmac_key, mac);
    return Arrays.copyOfRange(packet, 6, packet.length - 32);
  }
}
