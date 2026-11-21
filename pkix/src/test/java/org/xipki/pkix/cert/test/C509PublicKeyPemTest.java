// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.codec.c509.C509SubjectPublicKeyInfo;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.util.StringUtil;
import org.xipki.pkix.util.C509Util;
import org.xipki.util.misc.PemEncoder;

import java.io.IOException;

/**
 * C509SubjectPublicKeyInfo in PEM with the label C509 PUBLIC KEY.
 *
 * @author Lijun Liao (xipki)
 */
public class C509PublicKeyPemTest {

  private static C509SubjectPublicKeyInfo newKey() throws Exception {
    return new C509SubjectPublicKeyInfo(
        C509KeyPair.generateKeyPair(ConstPublicKeyAlgorithm.ec_secp256r1).subjectPublicKey());
  }

  @Test
  public void pemRoundTrip() throws Exception {
    C509SubjectPublicKeyInfo key = newKey();
    String pem = C509Util.toPemPublicKey(key);
    Assert.assertTrue(pem.startsWith("-----BEGIN C509 PUBLIC KEY-----\r\n"));
    Assert.assertTrue(pem.endsWith("\r\n-----END C509 PUBLIC KEY-----\r\n"));

    Assert.assertEquals(key, C509Util.parsePublicKey(StringUtil.toUtf8Bytes(pem)));
    // CBOR-encoded
    Assert.assertEquals(key, C509Util.parsePublicKey(key.getEncoded()));
  }

  @Test
  public void otherLabelsAreSkipped() throws Exception {
    C509SubjectPublicKeyInfo key = newKey();
    String pem = StringUtil.toUtf8String(
        PemEncoder.encode(new byte[] {1, 2, 3}, PemEncoder.PemLabel.PUBLIC_KEY))
        + C509Util.toPemPublicKey(key);
    Assert.assertEquals(key, C509Util.parsePublicKey(StringUtil.toUtf8Bytes(pem)));
  }

  @Test
  public void noC509PublicKey() {
    byte[] pem = PemEncoder.encode(new byte[] {1, 2, 3}, PemEncoder.PemLabel.PUBLIC_KEY);
    Assert.assertThrows(IOException.class, () -> C509Util.parsePublicKey(pem));
    Assert.assertThrows(IOException.class, () -> C509Util.parsePublicKey(new byte[] {1, 2}));
  }

}
