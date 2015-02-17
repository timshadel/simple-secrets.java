package com.timshadel.simplesecrets;

import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.msgpack.template.Templates.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Primitives.class)
@PowerMockIgnore({ "javax.crypto.*" })  // Avoids ClassCastException
public class CompatibilityTest {

    private static final String KEY = "eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad";
    private Packet sender;

    @Before
    public void before() throws Exception {
        PowerMockito.spy(Primitives.class);
        byte[] nonce = Hex.decodeHex("83dcf5916c0b5c4bc759e44f9f5c8c50".toCharArray());
        Mockito.when(Primitives.nonce()).thenReturn(nonce);
        sender = new Packet(KEY);
    }

    @Test
    public void testString() throws Exception {
        String string = "This is the simple-secrets compatibility standard string.";
        String websafeMsgpack1 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0";
        String websafeMsgpack5 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ";
        assertEquals(string, sender.unpack(websafeMsgpack1, String.class));
        assertEquals(string, sender.unpack(websafeMsgpack5, String.class));
        //assertEquals(websafeMsgpack5, sender.pack(string)); //TODO
    }

    @Test
    public void testNumbers() throws Exception {
        int integer = 65234;
        String websafeMsgpack = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yN5I1SH6a75Y_qQlQIclwrVyOk6jJJnMrjeOm6D27_wD0DxwIY9cxSw8boQDgEsLKg";
        assertEquals(integer, sender.unpack(websafeMsgpack, Integer.class).intValue());
        //assertEquals(websafeMsgpack, sender.pack(integer)); //TODO
    }

    @Test
    public void testNull() throws Exception {
        String websafeMsgpack = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPYBCYpYMU-4WChi6L1O1GCEApGRhWlg13kVPLTb90cXcEN9vpYgvttgcBJBh6Tjv8";
        assertNull(sender.unpack(websafeMsgpack, String.class));
        //assertEquals(websafeMsgpack, sender.pack(null)); //TODO
    }

    @Test
    public void testArray() throws Exception {
        String[] array = {"This is the simple-secrets compatibility standard array.", "This is the simple-secrets compatibility standard array."};
        String websafeMsgpack1 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMKAFsDUUYwc2fKvPhP_RHYhDOUfJ58li1gJgg9sVeaKx9yC0vFkpxuTmzJP6hZjn6XXlrG6A7-EeNgyzvP547booi2LUi0ALyAzbCaR8abXqnzoNwITRz7TL0J_NkP2gfxbpwUvyBo8ZT0cxGRr9jGnW5F5s6D0jmKZTl209nDJEpXDFRDXCo5y08tmvMNogs7rsZYz74mAap3mrBS-J7W";
        String websafeMsgpack5 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yP5Au9NtEbC-uoWkSPKgnAjODduuH_a2tH-zXaPNdqScWNR8snsQK2OufCVnb2OFk8O7VwgrObvx5gnGgC3pOsmk2Z5CasmOAfzn0B6uEnaBpiMOs74d0d70t07J4MdCRs1aDai9SJqxMpbjz5KJpVmSWqnT3n5KhzEdTLQwCuXQhSA0JKFaAlwQHh5tzq6ToWZZVR34REAGdAo7RMLSSi3";
        assertArrayEquals(array, sender.unpack(websafeMsgpack1, String[].class));
        assertArrayEquals(array, sender.unpack(websafeMsgpack5, String[].class));
        //assertEquals(websafeMsgpack5, sender.pack(array)); //TODO
    }

    @Test
    public void testMap() throws Exception {
        Map<String, String> map = new HashMap<String, String>();
        map.put("compatibility-key", "This is the simple-secrets compatibility standard map.");
        String websafeMsgpack1 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXYKrvvhyLbyFTsndgOx5M5yockEUwdSgv6jG_JYpAiU5R37Y7OIZnF3IN2EWtaFSuJko0ajcvoYgDPeLMvjAJdRyBUYIKcvR-g56_p4O7Uef3yJRnfCprG6jUdMyDBai_";
        String websafeMsgpack5 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXsI6Zwegq5A48uq2i-l13bNQWLY9Ho-lG_s6PzwQhjGz6BnCwAK66YsDBlTqflM-X1mviccZbvUV7K6i2ZPOs8gDUtMIVnu-ByDFopGwZUHjelkUZiLZcRKWXIYSLWyKp";
        assertEquals(map, sender.unpack(websafeMsgpack1, tMap(TString, TString)));
        assertEquals(map, sender.unpack(websafeMsgpack5, tMap(TString, TString)));
        //assertEquals(websafeMsgpack5, sender.pack(map)); //TODO
    }

    @Test
    public void testBinary() throws Exception {
        byte[] binary = new byte[10];
        Arrays.fill(binary, (byte) 0x32);
        String websafeMsgpack1 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yOnGuj4lHrhU_Uv8rMbpjXQJiqd3OMdktrw1asMDXy6jyLrVe9Ea-W09XC90Dgaxlk";
        String websafeMsgpack5 = "W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMVgYX8jn_wUmumA0aJMLlWffSYU0oaJsyJsVjxxF96Ia6mZgAalv5iywbsKORqxtQ";
        assertArrayEquals(binary, sender.unpack(websafeMsgpack1, byte[].class));
        assertArrayEquals(binary, sender.unpack(websafeMsgpack5, byte[].class));
        //assertEquals(websafeMsgpack5, sender.pack(binary)); //TODO
    }
}
