// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestamp;
import org.xipki.asn1.cert.CtLog.SignedCertificateTimestampList;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.Extension;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.io.XipkiIoUtil;

/**
 * CTLog test.
 *
 * @author Lijun Liao (xipki)
 */
public class CtLogTest {

  @Test
  public void parseCtLogInCerts() throws Exception {
    String[] certFiles = new String[]{"/ctlog-certs/githubcom.pem",
        "/ctlog-certs/cab-domain-validated1.crt"};

    for (String m : certFiles) {
      try {
        parseCtLogInCert(m);
      } catch (Exception ex) {
        throw new Exception("exception throw while parsing CT Log in file " + m, ex);
      }
    }
  }

  private void parseCtLogInCert(String certFile) throws Exception {
    byte[] certBytes = XipkiIoUtil.readAllBytesAndClose( getClass().getResourceAsStream(certFile));
    certBytes = X509Util.toDerEncoded(certBytes);
    Certificate cert = Certificate.fromEncoded(certBytes);
    Extension extn = cert.getTBSCertificate().getExtensions().getExtension(
        ExtensionOIDs.id_SignedCertificateTimestampList);

    byte[] encodedScts = extn.signedCertificateTimestampList();

    SignedCertificateTimestampList sctList2 =
        SignedCertificateTimestampList.getInstance(encodedScts);
    SignedCertificateTimestamp sct = sctList2.sctList().get(0);
    sct.digitallySigned().getEncoded();
    Object signatureObject = sctList2.sctList().get(0).digitallySigned()
        .signatureObject();
    Assert.assertNotNull("signatureObject", signatureObject);
    Assert.assertArrayEquals(encodedScts, sctList2.getEncoded());
  }

}
