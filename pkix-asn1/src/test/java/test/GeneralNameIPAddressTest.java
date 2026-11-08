// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.Hex;

/**
 * Tests for the IP address factory methods of {@link GeneralName}.
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralNameIPAddressTest {

  private static void assertEncoding(String expectedHex, String ip) {
    Assert.assertEquals(ip, expectedHex, Hex.encode(GeneralName.ofIPAddress(ip).IPAddress()));
    Assert.assertEquals(ip, expectedHex,
        Hex.encode(GeneralName.ofTagName(GeneralName.tag_iPAddress, ip).IPAddress()));
  }

  @Test
  public void validAddresses() {
    assertEncoding("c0a80105", "192.168.1.5");
    assertEncoding("c0a80105ffffff00", "192.168.1.5/24");
    assertEncoding("20010db8000000000000000000000001", "2001:db8::1");
    assertEncoding("00000000000000000000ffff01020304", "::ffff:1.2.3.4");
    assertEncoding("20010db8000000000000000000000001ffffffffffffffff0000000000000000",
        "2001:db8::1/64");
    // the mask starts with a colon.
    assertEncoding("0000000000000000000000000000000100000000000000000000000000000fff",
        "::1/::fff");
    assertEncoding("0000000000000000000000000000000000000000000000000000000000000000",
        "::/0");
  }

  @Test
  public void invalidAddress() {
    Assert.assertThrows(IllegalArgumentException.class, () -> GeneralName.ofIPAddress("1:2:"));
    Assert.assertThrows(IllegalArgumentException.class,
        () -> GeneralName.ofTagName(GeneralName.tag_iPAddress, "abc"));
  }

}
