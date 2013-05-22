package com.timshadel.simplesecrets;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.msgpack.MessagePack;
import org.msgpack.template.Template;

import static org.msgpack.template.Templates.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;


public class Primitives
{
  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final String KEY_ALGORITHM = "AES";
  private static final String DIGEST_ALGORITHM = "SHA-256";
  private static final String HMAC_ALGORITHM = "HmacSHA256";


  /**
   * Provide 16 securely random bytes.
   *
   * @return
   */
  public static byte[] nonce()
  {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }


  /**
   * Generate the authentication key for messages originating from the channel's Sender side.
   * <p/>
   * Uses the ASCII string 'simple-crypto/sender-hmac-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_sender_hmac(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/sender-hmac-key");
  }


  /**
   * Generate the encryption key for messages originating from the channel's Sender side.
   * <p/>
   * Uses the ASCII string 'simple-crypto/sender-cipher-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_sender_key(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/sender-cipher-key");
  }


  /**
   * Generate the authentication key for messages originating from the channel's Receiver side.
   * <p/>
   * Uses the ASCII string 'simple-crypto/receiver-hmac-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_receiver_hmac(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/receiver-hmac-key");
  }


  /**
   * Generate the encryption key for messages originating from the channel's Receiver side.
   * <p/>
   * Uses the ASCII string 'simple-crypto/receiver-cipher-key' as the role.
   *
   * @param master_key - the 256-bit master key of this secure channel
   * @return
   * @throws GeneralSecurityException
   */
  public static byte[] derive_receiver_key(final byte[] master_key)
          throws GeneralSecurityException
  {
    return derive(master_key, "simple-crypto/receiver-cipher-key");
  }


  /**
   * Encrypt buffer with the given key.
   * <p/>
   * Uses AES256 with a random 128-bit initialization vector.
   *
   * @param binary     - the plaintext binary string
   * @param master_key - the 256-bit encryption key
   * @return - a binary string of (IV + ciphertext)
   * @throws GeneralSecurityException
   */
  public static byte[] encrypt(final byte[] binary, final byte[] master_key)
          throws GeneralSecurityException
  {
    Utilities.assertBinary(binary);
    Utilities.assertBinarySize(master_key, 32);

    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    SecretKeySpec keySpec = new SecretKeySpec(master_key, KEY_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);

    byte[] iv_bytes = cipher.getIV();
    byte[] binary_bytes = cipher.update(binary);
    byte[] final_bytes = cipher.doFinal();

    byte[] encrypted = Utilities.joinByteArrays(iv_bytes, binary_bytes, final_bytes);
    return encrypted;
  }


  /**
   * Decrypt buffer with the given key and initialization vector.
   * <p/>
   * Uses AES256.
   *
   * @param binary     - ciphertext
   * @param master_key - the 256-bit encryption key
   * @param iv         - the 128-bit initialization vector
   * @return - plaintext binary string
   * @throws GeneralSecurityException
   */
  public static byte[] decrypt(final byte[] binary, final byte[] master_key, final byte[] iv)
          throws GeneralSecurityException
  {
    Utilities.assertBinary(binary);
    Utilities.assertBinarySize(master_key, 32);
    Utilities.assertBinarySize(iv, 16);

    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    SecretKeySpec keySpec = new SecretKeySpec(master_key, KEY_ALGORITHM);
    IvParameterSpec ivSpec = new IvParameterSpec(iv, 0, cipher.getBlockSize());
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    byte[] binary_bytes = cipher.update(binary);
    byte[] final_bytes = cipher.doFinal();

    byte[] decrypted = Utilities.joinByteArrays(binary_bytes, final_bytes);
    return decrypted;
  }


  /**
   * Create a short identifier for potentially sensitive data.
   *
   * @param binary - the data to identify
   * @return - 6-byte binary string identifier
   */
  public static byte[] identify(final byte[] binary)
          throws GeneralSecurityException
  {
    Utilities.assertBinary(binary);

    // This works for binaries of length 256-bytes or less.  Beyond that,
    // the values don't match those from the Ruby side.  We're only
    // expecting to use this with 32-byte master keys, so I did
    // not investigate further.
    // TODO: Figure out large-byte discrepancy between Java and Ruby identify values.
    MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
    digest.update(BigInteger.valueOf(binary.length).toByteArray());
    digest.update(binary);
    byte[] hash = digest.digest();
    return Arrays.copyOfRange(hash, 0, 6);
  }


  /**
   * Create a message authentication code for the given data.
   # Uses HMAC-SHA256.

   * @param binary - data to authenticate
   * @param hmac_key - the authentication key
   * @return - 32-byte MAC binary string
   * @throws GeneralSecurityException
   */
  public static byte[] mac(final byte[] binary, final byte[] hmac_key)
          throws GeneralSecurityException
  {
    Utilities.assertBinary(binary);
    Utilities.assertBinarySize(hmac_key,32);

    SecretKeySpec keySpec = new SecretKeySpec(hmac_key, HMAC_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_ALGORITHM);
    mac.init(keySpec);

    return mac.doFinal(binary);
  }


  /**
   * Use a constant-time comparison algorithm to reduce
   * side-channel attacks.
   *
   * Short-circuits only when the two buffers aren't the same length.
   *
   * @param a - a binary string
   * @param b - a binary string
   * @return true if both match
   */
  public static boolean compare(final byte[] a, final byte[] b)
  {
    Utilities.assertBinary(a);
    Utilities.assertBinary(b);

    // things must be the same length to compare them.
    if(a.length != b.length)
      return false;

    // constant-time compare
    //  hat-tip to https://github.com/freewil/scmp for |=
    int same = 0;
    for(int i = 0; i < a.length; i++)
    {
      same += a[i] ^ b[i];
    }

    return same == 0;
  }


  /**
   * Turn a websafe string back into a binary string.
   *
   * Uses base64url encoding.
   *
   * @param base64 - websafe string
   * @return - the binary version of this string
   */
  public static byte[] binify(final String base64)
  {
    if(base64 == null || Base64.isBase64(base64) == false)
      throw new IllegalArgumentException("Base64 string required.");

    String _base64;
    if(base64.length() % 4 != 0)
      _base64 = StringUtils.rightPad(base64, base64.length() + (4 - (base64.length() % 4)), '=');
    else
      _base64 = base64;
    return Base64.decodeBase64(_base64);
  }


  /**
   * Turn a binary buffer into a websafe string.
   *
   * Uses base64url encoding.
   *
   * @param binary - data which needs to be websafe
   * @return - the websafe string
   */
  public static String stringify(final byte[] binary)
  {
    Utilities.assertBinary(binary);

    return Base64.encodeBase64URLSafeString(binary);
  }


  /**
   * Turn a JSON-like object into a binary representation suitable for use in crypto functions.
   * This object will possibly be deserialized in a different programming environment—it should
   * be JSON-like in structure.
   *
   * Uses MsgPack data serialization.
   *
   * @param object - object to serialize
   * @return - the binary version of this object
   */
  public static byte[] serialize(final Object object)
          throws IOException
  {
    return new MessagePack().write(object);
  }


  /**
   * Turn a binary representation into an object suitable for use in application logic.
   * This object possibly originated in a different programming environment—it should be
   * JSON-like in structure.
   *
   * Uses MsgPack data serialization.
   *
   * The Class parameter is the class that MessagePack will try to return after
   * converting the binary data.  In most cases, simple classes or classes
   * annotated with @Message convert easily.  Collections and more complex
   * classes may need their own MessagePack converter class or need to use
   * the Template<T> version of this method.
   *
   * @link deserialize(final byte[] binary, final Template<T> template)
   *
   * See the MessagePack website for more information:
   *
   * @link http://msgpack.org/
   *
   * @param binary - a binary string version of the object
   * @param klass - the class of the object to be returned
   * @param <T>
   * @return - an object of the given class type
   * @throws IOException
   */
  public static <T> T deserialize(final byte[] binary, final Class<T> klass)
          throws IOException
  {
    Utilities.assertBinary(binary);
    if(klass == null)
      throw new IllegalArgumentException("Class type required for deserialization.");

    return new MessagePack().read(binary, klass);
  }


  /**
   * Turn a binary representation into an object suitable for use in application logic.
   * This object possibly originated in a different programming environment—it should be
   * JSON-like in structure.
   *
   * Uses MsgPack data serialization.
   *
   * The Template parameter is a MessagePack template, such as "tMap<TString, TValue>"
   * for a Map object with String keys.  The Value objects have methods to determine
   * their type and to return typed values.  See the MessagePack website for more
   * information:
   *
   * @link http://msgpack.org/
   *
   * @param binary - a binary string version of the object
   * @param template - the template of the object to be returned
   * @param <T>
   * @return - an object of the given class type
   * @throws IOException
   */
  public static <T> T deserialize(final byte[] binary, final Template<T> template)
          throws IOException
  {
    Utilities.assertBinary(binary);
    if(template == null)
      throw new IllegalArgumentException("Template type required for deserialization.");

    return new MessagePack().read(binary, template);
  }


  /**
   * Overwrite the contents of the byte array with zeroes.
   * This is critical for removing sensitive data from memory.
   *
   * @param binaries - byte arrays whose content should be wiped
   */
  public static void zero(byte[]... binaries)
  {
    if (binaries == null)
      return;

    for (byte[] binary : binaries) {
      if(binary == null)
        continue;

      for(int i = 0; i < binary.length; i++)
      {
        binary[i] = 0x00;
      }
    }
  }


  /**
   * Generate an encryption or hmac key from the master key and role.
   * <p/>
   * Uses SHA256(key || role).
   *
   * @param master_key
   * @param role
   * @return
   * @throws GeneralSecurityException
   * @todo link or citation
   */
  private static byte[] derive(final byte[] master_key, final String role)
          throws GeneralSecurityException
  {
    Utilities.assertBinarySize(master_key, 32);

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(master_key);
    digest.update(role.getBytes());
    return digest.digest();
  }


}