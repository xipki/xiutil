// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.C509TBSCertificate;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;

import java.time.Instant;

/**
 * Validity periods, in particular certificates without expiry.
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateValidityTest {

  @Test
  public void noExpiry() throws Exception {
    C509KeyPair caKey = TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1);
    C509Certificate ca = Fixtures.rootCa(caKey, "C=DE, CN=Validity Test CA");
    Assert.assertTrue(ca.isSelfSigned());

    C509Certificate cert = Fixtures.issue(caKey, ca, new C509Name("CN=no expiry"),
        TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1).subjectPublicKey(),
        C509TBSCertificate.NO_EXPIRY, null);
    Assert.assertEquals(C509TBSCertificate.NO_EXPIRY, cert.notAfter());
    Assert.assertTrue(cert.isValidAt(Instant.parse("9999-12-31T23:59:59Z")));

    // notAfter, the 6th element after type, serial, algorithm, issuer and notBefore, is null
    try (CborDecoder in = new ByteArrayCborDecoder(cert.getEncoded())) {
      in.readArrayLength(11);
      in.readInt();
      in.readByteString();
      in.readInt();
      C509Name.read(in);
      in.readLong();
      Assert.assertTrue("notAfter is null", in.peekType().isNull());
    }
  }

  @Test
  public void notAfterBeyondMaximumIsCapped() throws Exception {
    C509KeyPair key = TestKeys.generate(ConstPublicKeyAlgorithm.ed25519);
    C509Certificate cert = Fixtures.issue(key, null, new C509Name("CN=far future"),
        key.subjectPublicKey(), Instant.parse("+12000-01-01T00:00:00Z"), null);
    Assert.assertEquals(C509TBSCertificate.NO_EXPIRY, cert.notAfter());
  }

  @Test(expected = IllegalArgumentException.class)
  public void notAfterBeforeNotBefore() throws Exception {
    C509KeyPair key = TestKeys.generate(ConstPublicKeyAlgorithm.ed25519);
    Fixtures.issue(key, null, new C509Name("CN=invalid"), key.subjectPublicKey(),
        Instant.parse("2000-01-01T00:00:00Z"), null);
  }

}
