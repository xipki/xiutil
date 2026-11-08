// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.ipadress.IPAddressFamily;
import org.xipki.codec.ipadress.Rfc3779IPAddress;

/**
 * @author Lijun Liao (xipki)
 */
public class IPAddressTest {

  @Test
  public void executeTest() {
    int afi = IPAddressFamily.AFI_IPv4;
    Rfc3779IPAddress.Context context = Rfc3779IPAddress.Context.PREFIX;
    Rfc3779IPAddress addr0 = Rfc3779IPAddress.getIPv4Instance("12.34.56.78", context);
    Assert.assertEquals("12.34.56.78", "12.34.56.78/32", addr0.toString(afi, context));

    addr0 = Rfc3779IPAddress.getIPv4Instance("12.32.0.0/16", context);
    System.out.println(addr0.toString(afi, context) + ":" + addr0.unusedBits() +
        ": " + Hex.encode(addr0.value()));

    addr0 = Rfc3779IPAddress.getIPv4Instance("12.32.0.0/12", context);
    System.out.println(addr0.toString(afi, context) + ":" + addr0.unusedBits() +
        ": " + Hex.encode(addr0.value()));

    if (true) return;

    Rfc3779IPAddress addr = Rfc3779IPAddress.getIPv4Instance("10.0.0.1", context);
    Assert.assertEquals("10.0.0.1", "10.0.0.1/32", addr.toString(afi, context));

    addr = Rfc3779IPAddress.getIPv4Instance("10.0.1/24", context);
    Assert.assertEquals("10.0.1.0/24", "10.0.1.0/24", addr.toString(afi, context));

    context = Rfc3779IPAddress.Context.RANGE_MIN;
    addr = Rfc3779IPAddress.getIPv4Instance("10.2.0.0", context);

    Assert.assertEquals("10.2.0.0", "10.2.0.0", addr.toString(afi, context));

    // 10.4.255.255
    context = Rfc3779IPAddress.Context.RANGE_MAX;
    addr = Rfc3779IPAddress.getIPv4Instance("10.4.255.255", context);
    Assert.assertEquals("10.4.255.255", "10.4.255.255", addr.toString(afi, context));

    // 2002:1::/64
    afi = IPAddressFamily.AFI_IPv6;
    context = Rfc3779IPAddress.Context.PREFIX;

    String[] texts = {// "2003::/18", "2001:5::/32", "2a00::/12", "2002:1::/64",
        "2002:2::/56"};
    for (String text : texts) {
      addr = Rfc3779IPAddress.getIPv6Instance(text, context);
      Assert.assertEquals(text, text, addr.toString(afi, context));
    }

    context = Rfc3779IPAddress.Context.RANGE_MIN;
    addr = Rfc3779IPAddress.getIPv6Instance("2002:3::", context);
    Assert.assertEquals("2002:3::", "2002:3::", addr.toString(afi, context));

    context = Rfc3779IPAddress.Context.RANGE_MAX;
    addr = Rfc3779IPAddress.getIPv6Instance("2002:8::fff:ffff:ffff:ffff:ffff", context);
    Assert.assertEquals("2002:8::fff:ffff:ffff:ffff:ffff",
        "2002:8:0:fff:ffff:ffff:ffff:ffff", addr.toString(afi, context));
  }

}
