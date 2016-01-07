package com.timshadel.simplesecrets;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.internal.util.reflection.Whitebox;
import org.msgpack.template.Template;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.security.SecureRandom;

import static org.junit.Assert.*;
import static org.msgpack.template.Templates.TString;


@RunWith(PowerMockRunner.class)
@PrepareForTest(Primitives.class)
@PowerMockIgnore({ "javax.crypto.*" })  // Avoids ClassCastExceptions
public class CompatabilityTest
{
  private static final String MASTER_KEY = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";

  @Before
  public void mock_crypto() throws Exception {
        PowerMockito.spy(Primitives.class);
    byte[] bytes = hexStringToBytes("83dcf5916c0b5c4bc759e44f9f5c8c50");
    Mockito.when(Primitives.nonce()).thenReturn(bytes);

    SecureRandom mockRandom = Mockito.mock(SecureRandom.class);
    PowerMockito.whenNew(SecureRandom.class).withNoArguments().thenReturn(mockRandom);
    Mockito.doAnswer(new Answer() {
      @Override
      public Object answer(InvocationOnMock invocation) throws Throwable {
        Object[] args = invocation.getArguments();
        byte[] target = (byte[]) args[0];
        byte[] source = hexStringToBytes("7f3333233ce9235860ef902e6d0fcf35");
        System.arraycopy(source, 0, target, 0, source.length);
        return null;
      }
    }).when(mockRandom).nextBytes(Mockito.any(byte[].class));
  }

  @Test
  public void test_string()
          throws GeneralSecurityException, IOException
  {
    String data = "This is the simple-secrets compatibility standard string.";
    String packed_data = new Packet(MASTER_KEY).pack(data);
    String msgpack1 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0";
    assertEquals(msgpack1, packed_data);
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
