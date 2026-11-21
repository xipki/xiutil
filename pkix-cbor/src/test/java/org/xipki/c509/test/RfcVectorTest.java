// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.C509ECSubjectPublicKey;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.crypto.ContentVerifierFactory;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * The natively signed example certificate of the C509 draft, appendix A.1.
 *
 * @author Lijun Liao (xipki)
 */
public class RfcVectorTest {

  private static final String CA_POINT =
      "02AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA0080DF678867845E";

  private static final String[] EXAMPLE = {
      "8B",
      "02",
      "43 01 F5 0D",
      "00",
      "6B 52 46 43 20 74 65 73 74 20 43 41",
      "1A 63 B0 CD 00",
      "1A 69 55 B9 00",
      "47 01 01 23 45 67 89 AB",
      "01",
      "58 21 02 B1 21 6A B9 6E 5B 3B 33 40 F5 BD F0 2E 69 3F 16 21 3A 04 52",
      "5E D4 44 50 B1 01 9C 2D FD 38 38 AB",
      "01",
      "58 40 35 7B 3D 83 F4 EC D1 B4 E1 D2 25 A8 5C 6B E2 EA DA 31 34 37 5E",
      "72 E5 B6 E2 C3 11 FC 9F 3D D5 96 25 85 AB F6 44 D6 84 15 19 4C 24 5A",
      "57 9E 13 4A 7C A5 31 3B 90 AE AF CA A7 AF 0D E4 40 30 21 46"};

  @Test
  public void exampleCertificate() throws Exception {
    byte[] encoded = Hex.decode(String.join("", EXAMPLE).replace(" ", ""));
    C509Certificate cert = C509Certificate.parse(encoded);

    Assert.assertEquals(Hex.encode(encoded), Hex.encode(cert.getEncoded()));
    Assert.assertEquals(new BigInteger("01F50D", 16), cert.serialNumber());
    Assert.assertEquals("CN=RFC test CA", cert.issuer().getNameText());
    Assert.assertTrue(cert.extensions().hasKeyUsage(C509KeyUsage.DIGITAL_SIGNATURE));

    PublicKey caKey = TestKeys.toJca(new C509ECSubjectPublicKey(
        ConstPublicKeyAlgorithm.ec_secp256r1, Hex.decode(CA_POINT)));
    ContentVerifierFactory cvf = new TestKeys.MyContentVerifierFactory(caKey);
    Assert.assertTrue("signature", cert.verify(cvf));
  }

}
