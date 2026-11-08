// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.cms.ContentInfo;
import org.xipki.asn1.pkcs12.AuthenticatedSafe;
import org.xipki.asn1.pkcs12.MacData;
import org.xipki.asn1.pkcs12.Pfx;
import org.xipki.asn1.pkcs12.SafeBag;
import org.xipki.asn1.pkcs12.SafeContents;
import org.xipki.asn1.x509.Certificate;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.asn1.crypto.DigestInfo;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.Hex;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.cert.test.TestUtil;
import org.xipki.pkix.pkcs12.KeypairWithCert;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.pkcs12.Pkcs12Pbe;
import org.xipki.pkix.util.PKCS8Encryptor;
import org.xipki.util.misc.RandomUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Behaviour of {@link Pkcs12KeyStore}: reading files of xipki, OpenSSL and the JDK, round trips,
 * entries management, keys without certificate.
 *
 * @author Lijun Liao (xipki)
 */
public class Pkcs12KeyStoreTest {

  private static final String DIR = "src/test/resources/pkcs12test/";

  private static final char[] PWD_1234 = "1234".toCharArray();

  private static final SecureRandom RND = RandomUtil.random();

  // ---------------------------------------------------------------- reading

  @Test
  public void testXipkiFixtures() throws Exception {
    assertSingleKeyEntry("test1.p12", "1234", "main", null, 1);
    assertSingleKeyEntry("test1-enc.p12", "CHANGEIT", "main", null, 1);
    assertSingleKeyEntry("test-ec.p12", "1234", "main", null, 2);
  }

  /**
   * OpenSSL 3 default format: PBES2 (AES-256-CBC, PBKDF2-HMAC-SHA256), HMAC-SHA256 MAC, and a
   * 3-level chain.
   */
  @Test
  public void testOpensslChain() throws Exception {
    Pkcs12KeyStore ks = load("openssl/chain-pbes2.p12", PWD_1234);
    Assert.assertEquals(Collections.singleton("ee"), ks.aliases());
    Assert.assertTrue(ks.isKeyEntry("ee"));
    Assert.assertArrayEquals(read("openssl/ee-key.der"), ks.getKey("ee").getEncoded());

    List<Certificate> chain = ks.getCertificateChain("ee");
    Assert.assertEquals(3, chain.size());
    Assert.assertArrayEquals(read("openssl/ee-cert.der"), chain.get(0).getEncoded());
    Assert.assertArrayEquals(read("openssl/sub-cert.der"), chain.get(1).getEncoded());
    Assert.assertArrayEquals(read("openssl/root-cert.der"), chain.get(2).getEncoded());
    Assert.assertArrayEquals(read("openssl/ee-cert.der"), ks.getCertificate("ee").getEncoded());
  }

  @Test
  public void testOpensslPbmac1() throws Exception {
    Pkcs12KeyStore ks = load("openssl/pbmac1.p12", PWD_1234);
    Assert.assertEquals(Collections.singleton("ee"), ks.aliases());
    Assert.assertArrayEquals(read("openssl/ee-key.der"), ks.getKey("ee").getEncoded());
    Assert.assertArrayEquals(read("openssl/ee-cert.der"), ks.getCertificate("ee").getEncoded());
  }

  /**
   * Trusted certificate entry written by the JDK keytool (friendlyName + Oracle trusted key
   * usage).
   */
  @Test
  public void testJdkTrustedCert() throws Exception {
    Pkcs12KeyStore ks = load("jdk/trusted.p12", "123456".toCharArray());
    Assert.assertEquals(Collections.singleton("trusted-root"), ks.aliases());
    Assert.assertFalse(ks.isKeyEntry("trusted-root"));
    Assert.assertNull(ks.getKey("trusted-root"));
    Assert.assertNull(ks.getCertificateChain("trusted-root"));
    Assert.assertArrayEquals(read("openssl/root-cert.der"),
        ks.getCertificate("trusted-root").getEncoded());
  }

  /**
   * A certificate without friendlyName and without a key is not an entry.
   */
  @Test
  public void testCertWithoutName() throws Exception {
    Pkcs12KeyStore ks = load("openssl/trusted-noname.p12", PWD_1234);
    Assert.assertTrue(ks.aliases().isEmpty());
  }

  @Test
  public void testWrongPassword() throws Exception {
    for (String file : new String[]{"test1.p12", "openssl/chain-pbes2.p12", "openssl/pbmac1.p12"}) {
      try {
        load(file, "wrong".toCharArray());
        Assert.fail(file + ": IOException expected");
      } catch (IOException e) {
        // expected
      }
    }
  }

  @Test
  public void testEmptyStore() throws Exception {
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load((byte[]) null, null);
    Assert.assertTrue(ks.aliases().isEmpty());

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertTrue(ks2.aliases().isEmpty());
  }

  // ---------------------------------------------------------------- round trips

  @Test
  public void testRoundTripFixtures() throws Exception {
    String[][] fixtures = {{"test1.p12", "1234"}, {"test1-enc.p12", "CHANGEIT"},
        {"test-ec.p12", "1234"}, {"openssl/chain-pbes2.p12", "1234"},
        {"openssl/pbmac1.p12", "1234"}, {"jdk/trusted.p12", "123456"}};
    for (String[] f : fixtures) {
      Pkcs12KeyStore ks = load(f[0], f[1].toCharArray());
      Assert.assertEquals(f[0], snapshot(ks), snapshot(roundTrip(ks, PWD_1234)));
    }
  }

  @Test
  public void testRoundTripEmptyPassword() throws Exception {
    Pkcs12KeyStore ks = load("openssl/chain-pbes2.p12", PWD_1234);
    char[] empty = new char[0];
    Assert.assertEquals(snapshot(ks), snapshot(roundTrip(ks, empty)));
  }

  @Test
  public void testKeyAndTrustedEntries() throws Exception {
    Pkcs12KeyStore src = load("openssl/chain-pbes2.p12", PWD_1234);
    List<Certificate> chain = src.getCertificateChain("ee");

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load((byte[]) null, null);
    ks.setKeyEntry("key1", src.getKey("ee"), chain);
    ks.setCertificateEntry("root", chain.get(2));

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
    Assert.assertEquals(3, ks2.getCertificateChain("key1").size());
    Assert.assertFalse(ks2.isKeyEntry("root"));
  }

  // ---------------------------------------------------------------- entries

  @Test
  public void testReplaceKeyEntry() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    TestUtil.KeyAndCert ec = TestUtil.ec();

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.setKeyEntry("k", PrivateKeyInfo.fromPrivateKey(rsa.keyPair.getPrivate()), rsa.cert);
    ks.setKeyEntry("k", PrivateKeyInfo.fromPrivateKey(ec.keyPair.getPrivate()), ec.cert);

    Assert.assertEquals(Collections.singleton("k"), ks.aliases());
    Assert.assertArrayEquals(ec.keyPair.getPrivate().getEncoded(), ks.getKey("k").getEncoded());
    Assert.assertEquals(ec.cert, ks.getCertificate("k"));

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
  }

  @Test
  public void testCertificateEntryOnKeyAlias() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.setKeyEntry("k", PrivateKeyInfo.fromPrivateKey(rsa.keyPair.getPrivate()), rsa.cert);
    try {
      ks.setCertificateEntry("k", rsa.cert);
      Assert.fail("KeyStoreException expected");
    } catch (KeyStoreException e) {
      // expected
    }
  }

  @Test
  public void testSetKeyEntryInvalid() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    PrivateKeyInfo key = PrivateKeyInfo.fromPrivateKey(rsa.keyPair.getPrivate());
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    try {
      ks.setKeyEntry("k", null, rsa.cert);
      Assert.fail("KeyStoreException expected for null key");
    } catch (KeyStoreException e) {
      // expected
    }

    try {
      ks.setKeyEntry("k", key, Collections.emptyList());
      Assert.fail("KeyStoreException expected for empty chain");
    } catch (KeyStoreException e) {
      // expected
    }

    try {
      ks.setKeyEntry("k", key, Arrays.asList(rsa.cert, null));
      Assert.fail("KeyStoreException expected for chain with null element");
    } catch (KeyStoreException e) {
      // expected
    }
  }

  /**
   * The same certificate as two trusted entries, and as trusted entry and key certificate.
   */
  @Test
  public void testSameCertificateInSeveralEntries() throws Exception {
    Pkcs12KeyStore src = load("openssl/chain-pbes2.p12", PWD_1234);
    List<Certificate> chain = src.getCertificateChain("ee");

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.setKeyEntry("ee", src.getKey("ee"), chain);
    ks.setCertificateEntry("root-1", chain.get(2));
    ks.setCertificateEntry("root-2", chain.get(2));
    ks.setCertificateEntry("ee-cert", chain.get(0));

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertEquals(List.of("ee", "root-1", "root-2", "ee-cert").size(),
        ks2.aliases().size());
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
  }

  /**
   * Many trusted certificates and a key entry with a 3-level chain.
   */
  @Test
  public void testManyCertificates() throws Exception {
    Pkcs12KeyStore src = load("openssl/chain-pbes2.p12", PWD_1234);

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.setKeyEntry("ee", src.getKey("ee"), src.getCertificateChain("ee"));
    int n = 300;
    for (int i = 0; i < n; i++) {
      ks.setCertificateEntry("trusted-" + i, newSelfSignedCert("CN=Trusted " + i));
    }

    long start = System.nanoTime();
    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    long ms = (System.nanoTime() - start) / 1_000_000;
    System.out.println("store + load of " + (n + 1) + " entries: " + ms + " ms");

    Assert.assertEquals(n + 1, ks2.aliases().size());
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
    Assert.assertEquals(3, ks2.getCertificateChain("ee").size());
  }

  // ---------------------------------------------------------------- keys without certificate

  /**
   * A key with friendlyName but without localKeyId and without certificate (OpenSSL -nocerts).
   */
  @Test
  public void testKeyWithoutCertificate() throws Exception {
    Pkcs12KeyStore ks = load("openssl/nocerts.p12", PWD_1234);
    Assert.assertEquals(Collections.singleton("keyonly"), ks.aliases());
    Assert.assertTrue(ks.isKeyEntry("keyonly"));
    Assert.assertArrayEquals(read("openssl/ee-key.der"), ks.getKey("keyonly").getEncoded());
    Assert.assertNull(ks.getCertificate("keyonly"));
    Assert.assertEquals(Collections.emptyList(), ks.getCertificateChain("keyonly"));

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
  }

  /**
   * KeypairWithCert with a key without certificate in the keystore: works with an external
   * certificate chain, otherwise a clear error (not a NullPointerException).
   */
  @Test
  public void testKeypairWithCertForKeyWithoutCertificate() throws Exception {
    Pkcs12KeyStore ks = load("openssl/nocerts.p12", PWD_1234);
    X509Cert eeCert = new X509Cert(
        Certificate.fromEncoded(read("openssl/ee-cert.der")));

    KeypairWithCert kp =
        KeypairWithCert.fromKeystore(ks, "keyonly", PWD_1234,
            new X509Cert[]{eeCert});
    Assert.assertEquals(eeCert, kp.x509CertChain()[0]);

    try {
      KeypairWithCert.fromKeystore(ks, "keyonly", PWD_1234, null);
      Assert.fail("XiSecurityException expected");
    } catch (XiSecurityException e) {
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("no certificate for key"));
    }
  }

  /**
   * Two keys without any attributes and without certificates: both are kept.
   */
  @Test
  public void testKeysWithoutAttributes() throws Exception {
    byte[] key1 = PrivateKeyInfo.fromPrivateKey(TestUtil.rsa().keyPair.getPrivate()).getEncoded();
    byte[] key2 = PrivateKeyInfo.fromPrivateKey(TestUtil.ec().keyPair.getPrivate()).getEncoded();
    byte[] p12 = buildPkcs12WithKeysOnly(PWD_1234, key1, key2);

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load(p12, PWD_1234);
    Assert.assertEquals(2, ks.aliases().size());
    List<String> keys = new ArrayList<>();
    for (String alias : ks.aliases()) {
      Assert.assertTrue(alias, ks.isKeyEntry(alias));
      keys.add(Hex.encode(ks.getKey(alias).getEncoded()));
    }
    Collections.sort(keys);
    List<String> expected = new ArrayList<>(List.of(Hex.encode(key1), Hex.encode(key2)));
    Collections.sort(expected);
    Assert.assertEquals(expected, keys);

    Pkcs12KeyStore ks2 = roundTrip(ks, PWD_1234);
    Assert.assertEquals(snapshot(ks), snapshot(ks2));
  }

  // ---------------------------------------------------------------- helpers

  private static void assertSingleKeyEntry(String file, String password, String alias,
                                           String certFile, int chainSize) throws Exception {
    Pkcs12KeyStore ks = load(file, password.toCharArray());
    Assert.assertEquals(file, Collections.singleton(alias), ks.aliases());
    Assert.assertTrue(file, ks.isKeyEntry(alias));
    Assert.assertNotNull(file, ks.getKey(alias));
    Certificate cert = ks.getCertificate(alias);
    Assert.assertNotNull(file, cert);
    if (certFile != null) {
      Assert.assertArrayEquals(file, read(certFile), cert.getEncoded());
    }
    List<Certificate> chain = ks.getCertificateChain(alias);
    Assert.assertEquals(file, chainSize, chain.size());
    Assert.assertEquals(file, cert, chain.get(0));
  }

  static Pkcs12KeyStore load(String file, char[] password) throws Exception {
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load(read(file), password);
    return ks;
  }

  static byte[] read(String file) throws IOException {
    return Files.readAllBytes(Paths.get(DIR + file));
  }

  static Pkcs12KeyStore roundTrip(Pkcs12KeyStore ks, char[] password) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ks.store(out, password);
    Pkcs12KeyStore ks2 = new Pkcs12KeyStore();
    ks2.load(out.toByteArray(), password);
    return ks2;
  }

  /**
   * The content of the keystore: per alias whether it is a key entry, the SHA-256 of the key,
   * the SHA-256 of the certificate and the subjects of the chain.
   */
  static Map<String, String> snapshot(Pkcs12KeyStore ks) throws Exception {
    Map<String, String> ret = new TreeMap<>();
    for (String alias : ks.aliases()) {
      StringBuilder sb = new StringBuilder();
      sb.append("key=").append(ks.isKeyEntry(alias));
      PrivateKeyInfo key = ks.getKey(alias);
      sb.append(", keyHash=").append(key == null ? null : sha256(key.getEncoded()));
      Certificate cert = ks.getCertificate(alias);
      sb.append(", certHash=").append(cert == null ? null : sha256(cert.getEncoded()));
      List<Certificate> chain = ks.getCertificateChain(alias);
      if (chain == null) {
        sb.append(", chain=null");
      } else {
        List<String> subjects = new ArrayList<>();
        for (Certificate c : chain) {
          subjects.add(c.getSubject().toString());
        }
        sb.append(", chain=").append(subjects);
      }
      ret.put(alias, sb.toString());
    }
    return ret;
  }

  private static String sha256(byte[] data) throws Exception {
    return Hex.encode(MessageDigest.getInstance("SHA-256").digest(data)).substring(0, 16);
  }

  private static Certificate newSelfSignedCert(String subject) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    kpGen.initialize(new ECGenParameterSpec("secp256r1"), RND);
    KeyPair kp = kpGen.generateKeyPair();

    X500Name name = new X500Name(subject);
    long now = System.currentTimeMillis();
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
        BigInteger.valueOf(RND.nextLong() & Long.MAX_VALUE), new Date(now - 60_000),
        new Date(now + 86_400_000L), name, kp.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    builder.addExtension(Extension.subjectKeyIdentifier, false,
        new JcaX509ExtensionUtils().createSubjectKeyIdentifier(kp.getPublic()));
    byte[] encoded = builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
        .build(kp.getPrivate())).getEncoded();
    return Certificate.fromEncoded(encoded);
  }

  /**
   * Builds a PKCS#12 with shrouded key bags without any attributes and without certificates.
   */
  private static byte[] buildPkcs12WithKeysOnly(char[] password, byte[]... keys)
      throws Exception {
    List<SafeBag> bags = new ArrayList<>();
    for (byte[] key : keys) {
      bags.add(new SafeBag(PkcsOIDs.pkcs8ShroudedKeyBag,
          PKCS8Encryptor.encrypt(PrivateKeyInfo.fromEncoded(key), password)
              .toAsn1Primitive()));
    }

    ContentInfo keyContent = new ContentInfo(PkcsOIDs.data,
        new Asn1OctetString(new SafeContents(bags).getEncoded()));
    byte[] authSafe = new AuthenticatedSafe(keyContent).getEncoded();
    ContentInfo mainInfo = new ContentInfo(PkcsOIDs.data, new Asn1OctetString(authSafe));

    byte[] salt = new byte[20];
    RND.nextBytes(salt);
    AlgorithmIdentifier macAlg = AlgorithmIdentifier.ofNullParams(AlgorithmOIDs.id_sha1);
    byte[] mac = Pkcs12Pbe.calculatePbeMac(macAlg, salt, 1024, password, false, authSafe);
    return new Pfx(mainInfo, new MacData(new DigestInfo(macAlg, mac), salt, 1024)).getEncoded();
  }

}
