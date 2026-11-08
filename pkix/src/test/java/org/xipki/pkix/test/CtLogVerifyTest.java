// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.cert.CtLog;
import org.xipki.asn1.cert.CtLog.SerializedSCT;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestamp;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestampList;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.io.XipkiIoUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Public keys can be found under https://ct.grahamedgecombe.com/
 * @author Lijun Liao (xipki)
 */
public class CtLogVerifyTest {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private static final String pubkeyFile =
      "/ctlog-certs/letsencrypt/google-xenon2020-pubkey.pem";

  private static final String certFile =
      "/ctlog-certs/letsencrypt/letsencrypt-org.pem";

  private static final String caCertFile =
      "/ctlog-certs/letsencrypt/ca-of-letsencrypt-org.pem";

  @Test
  public void testVerify() throws Exception {
    byte[] keyBytes = read(pubkeyFile);

    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromEncoded(X509Util.toDerEncoded(keyBytes));
    byte[] keyId = HashAlgo.SHA256.hash(spki.getEncoded());
    System.out.println("keyId: " + Hex.encode(keyId));

    PublicKey key = KeyInfoUtil.getPublicKey(spki);
    X509Cert cert = X509Util.parseCert(read(certFile));
    X509Cert caCert = X509Util.parseCert(read(caCertFile));

    byte[] issuerKeyHash = HashAlgo.SHA256.hash( caCert.subjectPublicKeyInfo().getEncoded());
    byte[] preCertTbsCert = CtLog.getPreCertTbsCert(cert.getCert().getTBSCertificate());

    byte[] encodedScts = cert.getCert().getExtension(
        ExtensionOIDs.id_SignedCertificateTimestampList).signedCertificateTimestampList();
    SignedCertificateTimestampList list =
        SignedCertificateTimestampList.getInstance(encodedScts);
    SerializedSCT sctList = list.sctList();
    int size = sctList.size();
    Assert.assertEquals("SCT size", 2, size);

    SignedCertificateTimestamp sct = sctList.get(1);
    byte[] logId = sct.logId();
    Assert.assertEquals("logId", Hex.encodeUpper(keyId), Hex.encodeUpper(logId));

    Signature sig = cryptoApi.newSignature("SHA256withECDSA");
    sig.initVerify(key);
    CtLog.update(sig, (byte) sct.version(), sct.timestamp(),
        sct.extensions(), issuerKeyHash, preCertTbsCert);

    boolean sigValid = sig.verify(sct.digitallySigned().signature());
    Assert.assertTrue("signature valid", sigValid);
  }

  public static byte[] read(String name) throws IOException {
    InputStream is = CtLogVerifyTest.class.getResourceAsStream(name);
    if (is == null) {
      throw new IOException("could not find " + name);
    }
    return XipkiIoUtil.readAllBytesAndClose(is);
  }

}
