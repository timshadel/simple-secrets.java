package com.github.timshadel.simplesecrets;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class PrimitivesTest
{
  @Test
  public void test_nonce()
  {
    byte[] nonce = Primitives.nonce();
    assertEquals("Nonce is 16 bytes", 16, nonce.length);

    byte[] another_nonce = Primitives.nonce();
    assertFalse("Nonce is not repeated", Arrays.equals(nonce, another_nonce));
  }
}