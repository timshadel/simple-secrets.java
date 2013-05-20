package com.github.timshadel.simplesecrets;


import org.junit.Test;
import org.powermock.reflect.Whitebox;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Created with IntelliJ IDEA.
 * User: jay.wagnon
 * Date: 5/20/13
 * Time: 10:44 AM
 * To change this template use File | Settings | File Templates.
 */
public class UtilitiesTest
{
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
