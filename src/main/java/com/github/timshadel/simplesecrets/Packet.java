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

    try {
      this.master_key = Hex.decodeHex(master_key.toCharArray());
    }
    catch (DecoderException e) {
      throw new IllegalArgumentException("Invalid hexidecimal key.", e);
    }

    identity = Primitives.identify(this.master_key);
  }


  public static byte[] build_body(Object data)
          throws IOException
  {
    byte[] nonce = Primitives.nonce();
    byte[] binary = Primitives.serialize(data);

    byte[] body = Utilities.joinByteArrays(nonce, binary);

    Primitives.zero(nonce, binary);
    return body;
  }


  public static <T> T body_to_data(final byte[] body, final Class<T> klass)
          throws GeneralSecurityException, IOException
  {
    // Must at least have a nonce
    if(body.length < 16)
      throw new GeneralSecurityException("Invalid serialized payload.");

    byte[] nonce = Arrays.copyOfRange(body, 0, 16);
    byte[] payload = Arrays.copyOfRange(body, 16, body.length);

    T data = Primitives.deserialize(payload, klass);

    Primitives.zero(nonce, payload);
    return data;
  }


  public static byte[] encrypt_body(final byte[] body, final byte[] master_key)
          throws GeneralSecurityException
  {
    byte[] key = Primitives.derive_sender_key(master_key);

    byte[] cipher_data = Primitives.encrypt(body, key);

    Primitives.zero(key);
    return cipher_data;
  }


  public static byte[] decrypt_body(final byte[] cipher_data, final byte[] master_key)
          throws GeneralSecurityException
  {
    // Must at least have an iv
    if(cipher_data.length < 16)
      throw new GeneralSecurityException("Invalid encrypted payload.");

    byte[] key = Primitives.derive_sender_key(master_key);
    byte[] iv = Arrays.copyOfRange(cipher_data, 0, 16);
    byte[] encrypted = Arrays.copyOfRange(cipher_data, 16, cipher_data.length);

    byte[] body = Primitives.decrypt(encrypted, key, iv);

    Primitives.zero(key, iv, encrypted);
    return body;
  }


  public static byte[] authenticate(final byte[] data, final byte[] master_key, final byte[] identity)
          throws GeneralSecurityException
  {
    byte[] hmac_key = Primitives.derive_sender_hmac(master_key);

    byte[] auth = Utilities.joinByteArrays(identity, data);
    byte[] mac = Primitives.mac(auth, hmac_key);
    byte[] packet = Utilities.joinByteArrays(auth, mac);

    Primitives.zero(hmac_key, mac);
    return packet;
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
