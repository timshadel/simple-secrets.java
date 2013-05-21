package com.timshadel.simplesecrets;


import org.junit.Test;
import org.powermock.reflect.Whitebox;

import java.util.Arrays;

import static org.junit.Assert.*;


public class UtilitiesTest
{
  @Test
  public void constructor()
  {
    Object object = new Utilities();
    assertNotNull(object);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinary_null()
          throws Exception
  {
    Whitebox.invokeMethod(Utilities.class, "assertBinary", (byte[]) null);
  }


  @Test
  public void test_assertBinary()
          throws Exception
  {
    Whitebox.invokeMethod(Utilities.class, "assertBinary", new byte[16]);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinarySize_null_binary()
          throws Exception
  {
    Whitebox.invokeMethod(Utilities.class, "assertBinarySize", (byte[]) null, 1);
  }


  @Test(expected = IllegalArgumentException.class)
  public void test_assertBinarySize_invalid_size()
          throws Exception
  {
    Whitebox.invokeMethod(Utilities.class, "assertBinarySize", new byte[16], 1);
  }


  @Test
  public void test_assertBinarySize()
          throws Exception
  {
    Whitebox.invokeMethod(Utilities.class, "assertBinarySize", new byte[16], 16);
  }


  @Test
  public void test_joinByteArrays_null()
          throws Exception
  {
    byte[] result = Whitebox.invokeMethod(Utilities.class, "joinByteArrays", (byte[]) null);
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
    byte[] result = Whitebox.invokeMethod(Utilities.class, "joinByteArrays", array1, array2, array3, array4);
    assertNotNull(result);
    assertEquals(10, result.length);
    assertTrue(Arrays.equals("1234567890".getBytes(), result));
  }
}
