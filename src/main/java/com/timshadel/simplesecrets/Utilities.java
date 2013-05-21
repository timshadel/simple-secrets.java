package com.timshadel.simplesecrets;


public class Utilities
{
  /**
   * Asserts that the given byte array is non-null.
   * <p/>
   * Throws IllegalArgumentException if not.
   *
   * @param binary
   * @throws IllegalArgumentException
   */
  public static void assertBinary(final byte[] binary)
  {
    if (binary == null)
      throw new IllegalArgumentException("Byte array required.");
  }


  /**
   * Asserts that the given byte array is non-null and of the given size.
   * <p/>
   * Throws IllegalArgumentException if not.
   *
   * @param binary
   * @param bytes
   * @throws IllegalArgumentException
   */
  public static void assertBinarySize(final byte[] binary, int bytes)
  {
    if (binary == null || binary.length != bytes)
      throw new IllegalArgumentException((bytes * 8) + "-bit byte array required.");
  }


  /**
   * Takes a series of byte arrays and joins them into a single array.
   *
   * @param binaries
   * @return
   */
  public static byte[] joinByteArrays(final byte[]... binaries)
  {
    int size = 0;
    if (binaries[0] == null)
      return new byte[0];

    for (byte[] binary : binaries) {
      size += binary.length;
    }

    int index = 0;
    byte[] result = new byte[size];
    for (byte[] binary : binaries) {
      System.arraycopy(binary, 0, result, index, binary.length);
      index += binary.length;
    }

    return result;
  }
}
