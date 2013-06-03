package com.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.Whitebox;
import org.msgpack.template.Template;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.msgpack.template.Templates.TString;


@RunWith(PowerMockRunner.class)
@PrepareForTest(Primitives.class)
@PowerMockIgnore({ "javax.crypto.*" })  // Avoids ClassCastExceptions
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
  public void test_constructor_empty_key()
          throws GeneralSecurityException
  {
    new Packet("");
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
    byte[] body = Packet.build_body("abcd");

    // First 16 bytes will be unpredictable nonce.
    // Remaining bytes will be a serialization of the object.
    assertEquals(21, body.length);

    byte[] expected = new byte[]{ -92, 97, 98, 99, 100 };
    assertTrue(Arrays.equals(expected, Arrays.copyOfRange(body, 16, body.length)));
  }

  @Test(expected = IOException.class)
  public void test_build_body_finally_block()
          throws GeneralSecurityException, IOException
  {
    PowerMockito.mockStatic(Primitives.class);
    Mockito.when(Primitives.serialize(Mockito.any(byte[].class))).thenThrow(new IOException());
    Packet.build_body(null);
  }


  @Test(expected = GeneralSecurityException.class)
  public void test_body_to_data_too_short()
          throws GeneralSecurityException, IOException
  {
    byte[] body = new byte[15];
    Packet.body_to_data(body, String.class);
  }

  @Test
  public void test_body_to_data_class()
          throws GeneralSecurityException, IOException
  {
    byte[] nonce = Primitives.nonce();
    byte[] data = new byte[]{ -92, 97, 98, 99, 100 };

    byte[] body = Utilities.joinByteArrays(nonce, data);

    assertEquals("abcd", Packet.body_to_data(body, String.class));
  }

  @Test
  public void test_body_to_data_template()
          throws GeneralSecurityException, IOException
  {
    byte[] nonce = Primitives.nonce();
    byte[] data = new byte[]{ -92, 97, 98, 99, 100 };

    byte[] body = Utilities.joinByteArrays(nonce, data);

    assertEquals("abcd", Packet.body_to_data(body, TString));
  }


  @Test(expected = IOException.class)
  public void test_body_to_data_class_finally_block()
          throws GeneralSecurityException, IOException
  {
    PowerMockito.mockStatic(Primitives.class);
    Mockito.when(Primitives.deserialize(Mockito.any(byte[].class), Mockito.any(Class.class))).thenThrow(new IOException());

    byte[] nonce = new byte[16];
    byte[] data = new byte[]{ -92, 97, 98, 99, 100 };

    byte[] body = Utilities.joinByteArrays(nonce, data);
    Packet.body_to_data(body, String.class);
  }


  @Test(expected = IOException.class)
  public void test_body_to_data_template_finally_block()
          throws GeneralSecurityException, IOException
  {
    PowerMockito.mockStatic(Primitives.class);
    Mockito.when(Primitives.deserialize(Mockito.any(byte[].class), Mockito.any(Template.class))).thenThrow(new IOException());

    byte[] nonce = new byte[16];
    byte[] data = new byte[]{ -92, 97, 98, 99, 100 };

    byte[] body = Utilities.joinByteArrays(nonce, data);
    Packet.body_to_data(body, TString);
  }


  @Test
  public void test_encrypt_body_and_decrypt_body()
          throws GeneralSecurityException, IOException
  {
    byte[] body = Packet.build_body("abcd");

    byte[] encrypted = Packet.encrypt_body(body, hexStringToBytes(MASTER_KEY));
    byte[] decrypted = Packet.decrypt_body(encrypted, hexStringToBytes(MASTER_KEY));

    assertFalse(Arrays.equals(encrypted, decrypted));
    assertTrue(Arrays.equals(body, decrypted));
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_decrypt_body_too_short()
          throws GeneralSecurityException, IOException
  {
    byte[] body = new byte[15];
    Packet.decrypt_body(body, hexStringToBytes(MASTER_KEY));
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_encrypt_finally_block()
          throws GeneralSecurityException
  {
    PowerMockito.mockStatic(Primitives.class);
    Mockito.when(Primitives.encrypt(Mockito.any(byte[].class), Mockito.any(byte[].class))).thenThrow(new GeneralSecurityException());

    Packet.encrypt_body(new byte[48], hexStringToBytes(MASTER_KEY));
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_decrypt_finally_block()
          throws GeneralSecurityException, IOException
  {
    Packet.decrypt_body(new byte[48], hexStringToBytes(MASTER_KEY));
  }


  @Test(expected = GeneralSecurityException.class)
  public void test_authenticate_and_verify_invalid_identity()
          throws GeneralSecurityException, IOException
  {
    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);

    Packet.verify(new byte[5], key, identity);
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_authenticate_and_verify_bad_identity()
          throws GeneralSecurityException, IOException
  {
    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);
    byte[] bad_identity = hexStringToBytes("fd", 6);
    byte[] body = Packet.build_body("abcd");

    byte[] packet = Packet.authenticate(body, key, bad_identity);

    Packet.verify(packet, key, identity);
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_authenticate_and_verify_invalid_mac()
          throws GeneralSecurityException, IOException
  {
    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);
    byte[] body = Utilities.joinByteArrays(identity, new byte[31]);

    Packet.verify(body, key, identity);
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_authenticate_and_verify_bad_mac()
          throws GeneralSecurityException, IOException
  {
    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);
    byte[] body = Packet.build_body("abcd");

    byte[] packet = Packet.authenticate(body, key, identity);
    Arrays.fill(packet, packet.length - 32, packet.length, (byte)0xFD);  // Bad MAC

    Packet.verify(packet, key, identity);
  }

  @Test
  public void test_authenticate_and_verify()
          throws GeneralSecurityException, IOException
  {
    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);
    byte[] body = Packet.build_body("abcd");

    byte[] packet = Packet.authenticate(body, key, identity);
    byte[] data = Packet.verify(packet, key, identity);
    assertTrue(Arrays.equals(body, data));
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_authenticate_finally_block()
          throws GeneralSecurityException, IOException
  {
    PowerMockito.mockStatic(Primitives.class);
    Mockito.when(Primitives.mac(Mockito.any(byte[].class), Mockito.any(byte[].class))).thenThrow(new GeneralSecurityException());

    byte[] key = hexStringToBytes(MASTER_KEY);
    byte[] identity = Primitives.identify(key);
    byte[] body = Packet.build_body("abcd");
    Packet.authenticate(body, key, identity);
  }


  @Test
  public void test_pack_and_unpack_class()
          throws GeneralSecurityException, IOException
  {
    String data = "This is a secret message!";

    String packed_data = new Packet(MASTER_KEY).pack(data);

    String decrypted = new Packet(MASTER_KEY).unpack(packed_data, String.class);
    assertEquals(data, decrypted);
  }

  @Test
  public void test_pack_and_unpack_template()
          throws GeneralSecurityException, IOException
  {
    String data = "This is a secret message!";

    String packed_data = new Packet(MASTER_KEY).pack(data);

    String decrypted = new Packet(MASTER_KEY).unpack(packed_data, TString);
    assertEquals(data, decrypted);
  }

  @Test(expected = GeneralSecurityException.class)
  public void test_pack_and_unpack_with_different_key()
          throws GeneralSecurityException, IOException
  {
    String data = "This is a secret message!";

    String packed_data = new Packet(MASTER_KEY).pack(data);

    new Packet(hexString("fd", 32)).unpack(packed_data, String.class);
  }

  @Test(expected = IOException.class)
  public void test_pack_finally_block()
          throws GeneralSecurityException, IOException
  {
    PowerMockito.spy(Primitives.class);
    Mockito.when(Primitives.serialize(Mockito.any())).thenThrow(new IOException());
    new Packet(MASTER_KEY).pack("abcd");
  }

  // Coverage test
  @Test(expected = IllegalArgumentException.class)
  public void test_unpack_class_finally_block()
          throws GeneralSecurityException, IOException
  {
    new Packet(MASTER_KEY).unpack(null, String.class);
  }

  // Coverage test
  @Test(expected = IllegalArgumentException.class)
  public void test_unpack_template_finally_block()
          throws GeneralSecurityException, IOException
  {
    new Packet(MASTER_KEY).unpack(null, TString);
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
