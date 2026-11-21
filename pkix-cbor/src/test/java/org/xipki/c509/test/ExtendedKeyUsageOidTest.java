// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.id.KeyPurposeOIDs;

/**
 * Tests the mapping between C509 extended key usage codes and OIDs.
 *
 * @author Lijun Liao (xipki)
 */
public class ExtendedKeyUsageOidTest {

  private static final long[] CODES = {0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20};

  @Test
  public void roundTrip() {
    for (long code : CODES) {
      Asn1Oid oid = ConstExtendedKeyUsage.getOid(code);
      Assert.assertNotNull("OID of code " + code, oid);
      Assert.assertEquals(Long.valueOf(code), ConstExtendedKeyUsage.getCode(oid));
      Assert.assertEquals(Long.valueOf(code), ConstExtendedKeyUsage.getCode(oid.getId()));
    }
  }

  @Test
  public void knownValues() {
    Assert.assertEquals("1.3.6.1.5.5.7.3.1",
        ConstExtendedKeyUsage.getOid(ConstExtendedKeyUsage.serverAuth).getId());
    Assert.assertEquals("1.3.6.1.4.1.45605.1",
        ConstExtendedKeyUsage.getOid(ConstExtendedKeyUsage.wisun_fan_device).getId());
    Assert.assertEquals(Long.valueOf(ConstExtendedKeyUsage.pkinit_KPKdc),
        ConstExtendedKeyUsage.getCode("1.3.6.1.5.2.3.5"));
  }

  @Test
  public void unknown() {
    Assert.assertNull(ConstExtendedKeyUsage.getOid(5));
    Assert.assertNull(ConstExtendedKeyUsage.getOid(19));
    Assert.assertNull(ConstExtendedKeyUsage.getCode(KeyPurposeOIDs.id_kp_ipsecIKE));
    Assert.assertNull(ConstExtendedKeyUsage.getCode((Asn1Oid) null));
  }

}
