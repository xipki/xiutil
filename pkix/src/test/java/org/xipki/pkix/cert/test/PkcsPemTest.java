// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert.test;

import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.crypto.PBES2Parameters;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.EncryptedPrivateKeyInfo;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.crypto.core.pem.PemHeader;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.util.PKCS8Encryptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Tests of PKCS#12, encrypted PKCS#8 and PEM, against the JDK and BouncyCastle.
 *
 * @author Lijun Liao (xipki)
 */
public class PkcsPemTest {

  private static final char[] PASSWORD = "p12-password".toCharArray();

  @Test
  public void testPkcs12ToJdk() throws Exception {
    for (TestUtil.KeyAndCert kc : new TestUtil.KeyAndCert[]{TestUtil.rsa(), TestUtil.ec()}) {
      Pkcs12KeyStore ks = new Pkcs12KeyStore();
      ks.setKeyEntry("main", PrivateKeyInfo.fromPrivateKey(kc.keyPair.getPrivate()), kc.cert);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ks.store(out, PASSWORD);

      // the PKCS#12 keystore of the JDK (SunJSSE) reads it
      KeyStore jdkKs = KeyStore.getInstance("PKCS12", "SUN");
      jdkKs.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
      Assert.assertEquals(Collections.singletonList("main"), Collections.list(jdkKs.aliases()));
      Key key = jdkKs.getKey("main", PASSWORD);
      Assert.assertArrayEquals(kc.keyPair.getPrivate().getEncoded(), key.getEncoded());
      Assert.assertArrayEquals(kc.cert.getEncoded(),
          jdkKs.getCertificate("main").getEncoded());

      // and xipki reads it back
      Pkcs12KeyStore ks2 = new Pkcs12KeyStore();
      ks2.load(out.toByteArray(), PASSWORD);
      Assert.assertTrue(ks2.isKeyEntry("main"));
      Assert.assertArrayEquals(kc.keyPair.getPrivate().getEncoded(),
          ks2.getKey("main").getEncoded());
    }
  }

  @Test
  public void testPkcs12FromJdk() throws Exception {
    TestUtil.KeyAndCert kc = TestUtil.rsa();
    X509Certificate jceCert = kc.jceCert();

    KeyStore jdkKs = KeyStore.getInstance("PKCS12", "SUN");
    jdkKs.load(null, null);
    jdkKs.setKeyEntry("main", kc.keyPair.getPrivate(), PASSWORD,
        new java.security.cert.Certificate[]{jceCert});
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    jdkKs.store(out, PASSWORD);

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load(out.toByteArray(), PASSWORD);
    Assert.assertEquals(Collections.singleton("main"), ks.aliases());
    Assert.assertTrue(ks.isKeyEntry("main"));
    Assert.assertArrayEquals(kc.keyPair.getPrivate().getEncoded(), ks.getKey("main").getEncoded());

    List<Certificate> chain = ks.getCertificateChain("main");
    Assert.assertEquals(1, chain.size());
    Assert.assertArrayEquals(jceCert.getEncoded(), chain.get(0).getEncoded());
  }

  @Test
  public void testEncryptedPkcs8() throws Exception {
    for (TestUtil.KeyAndCert kc : new TestUtil.KeyAndCert[]{TestUtil.rsa(), TestUtil.ec()}) {
      PrivateKey key = kc.keyPair.getPrivate();
      EncryptedPrivateKeyInfo encKey = PKCS8Encryptor.encrypt(
          PrivateKeyInfo.fromPrivateKey(key), PASSWORD);
      // PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC
      Assert.assertEquals(PkcsOIDs.id_PBES2, encKey.getEncryptionAlgorithm().getAlgorithm());
      PBES2Parameters params = PBES2Parameters.fromAsn1(
          encKey.getEncryptionAlgorithm().getParameters().asSequence());
      Assert.assertEquals(NistOIDs.id_aes256_CBC, params.getEncryptionScheme().getAlgorithm());
      Assert.assertEquals(PkcsOIDs.id_PBKDF2, params.getKeyDerivationFunc().getAlgorithm());
      Assert.assertEquals(PkcsOIDs.id_hmacWithSHA256, PBKDF2Params.fromAsn1(
          params.getKeyDerivationFunc().getParameters().asSequence()).getPrf().getAlgorithm());

      // BouncyCastle decrypts it, as OpenSSL does
      PKCS8EncryptedPrivateKeyInfo bcInfo = new PKCS8EncryptedPrivateKeyInfo(encKey.getEncoded());
      byte[] decrypted = bcInfo.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder()
          .setProvider(TestUtil.BC).build(PASSWORD)).getEncoded();
      Assert.assertArrayEquals(key.getEncoded(), decrypted);
    }
  }

  @Test
  public void testPemWithHeaders() throws Exception {
    byte[] content = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    String b64 = Base64.getEncoder().encodeToString(content);
    String text = "garbage before\n"
        + "-----BEGIN RSA PRIVATE KEY-----\n"
        + "Proc-Type: 4,ENCRYPTED\n"
        + "DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n"
        + "\n"
        + b64 + "\n"
        + "-----END RSA PRIVATE KEY-----\n"
        + "-----BEGIN CERTIFICATE-----\n"
        + b64 + "\n"
        + "-----END CERTIFICATE-----\n";

    try (PemReader reader = new PemReader(new StringReader(text))) {
      PemObject obj = reader.readPemObject();
      Assert.assertEquals("RSA PRIVATE KEY", obj.getType());
      Assert.assertArrayEquals(content, obj.getContent());
      List<PemHeader> headers = obj.getHeaders();
      Assert.assertEquals(2, headers.size());
      Assert.assertEquals("Proc-Type", headers.get(0).getName());
      Assert.assertEquals("4,ENCRYPTED", headers.get(0).getValue());
      Assert.assertEquals("DEK-Info", headers.get(1).getName());

      obj = reader.readPemObject();
      Assert.assertEquals("CERTIFICATE", obj.getType());
      Assert.assertTrue(obj.getHeaders().isEmpty());
      Assert.assertArrayEquals(content, obj.getContent());

      Assert.assertNull(reader.readPemObject());
    }

    // PemObject with headers, to be written by a PEM writer
    PemObject obj = new PemObject("RSA PRIVATE KEY",
        List.of(new PemHeader("Proc-Type", "4,ENCRYPTED")), content);
    Assert.assertEquals(new PemHeader("Proc-Type", "4,ENCRYPTED"), obj.getHeaders().get(0));
  }

}
