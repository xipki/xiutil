// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.keycerts.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.Certificate;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.codec.util.IoUtil;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * @author Lijun Liao (xipki)
 */
public class CollectedPkcs12KeyStoreTest {

  @Test
  public void pkcs12LoadTest() throws Exception {
    for (Path path : CollectedCertTest.listFiles("/keycerts", "p12")) {
      try {
        Pkcs12KeyStore ks = Pkcs12KeyStore.fromEncoded(
            IoUtil.read(path.toFile()), "CHANGEIT".toCharArray());
        Set<String> aliases = ks.aliases();
        Assert.assertFalse("aliases", aliases.isEmpty());

        for (String alias : aliases) {
          if (ks.isKeyEntry(alias)) {
            List<Certificate> certs = ks.getCertificateChain(alias);
            Assert.assertNotNull("getCertificateChain", certs);
            // we do not have empty certs in the examples
            Assert.assertFalse("aliases", certs.isEmpty());
            for (Certificate cert : certs) {
              System.out.println(cert);
            }
          } else {
            Certificate cert = ks.getCertificate(alias);
            System.out.println(cert);
          }
        }
      } catch (Exception e) {
        throw new Exception("error loading " + path, e);
      }
    }
  }

}
