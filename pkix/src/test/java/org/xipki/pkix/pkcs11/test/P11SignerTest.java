// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs11.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.SecurityFactoryImpl;
import org.xipki.pkix.pkcs11.P11CompositeKey;
import org.xipki.pkix.pkcs11.P11CryptServiceFactory;
import org.xipki.pkix.pkcs11.P11Module;
import org.xipki.pkix.pkcs11.P11SignerFactory;
import org.xipki.pkix.pkcs11.P11Slot;
import org.xipki.pkix.pkcs11.P11SystemConf;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.CsrControl;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509KeyUtil;

import java.math.BigInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Signs with keys in a PKCS#11 token and verifies the signatures in software.
 *
 * @author Lijun Liao (xipki)
 */
public class P11SignerTest {

  private static final String MODULE = "default";

  private static final String PKCS11_CONF = "{\"modules\":[{"
      + "\"name\":\"" + MODULE + "\", \"readonly\":false, \"user\":\"CKU_USER\","
      + "\"numSessions\":4, \"includeSlots\":[{\"index\":0}],"
      + "\"nativeLibraries\":[{\"path\":\"xihsm:mem:vendor=xihsm\"}],"
      + "\"passwordSets\":[{\"passwords\":[\"123456\"]}]}]}";

  private static final byte[] DATA = "data to be signed".getBytes(StandardCharsets.US_ASCII);

  private static P11CryptServiceFactory p11Factory;

  @BeforeClass
  public static void init() throws Exception {
    p11Factory = new P11CryptServiceFactory();
    p11Factory.setPkcs11Conf(P11SystemConf.parse(JsonParser.parseMap(PKCS11_CONF, false)));
    p11Factory.init();
  }

  @AfterClass
  public static void shutdown() {
    if (p11Factory != null) {
      p11Factory.close();
    }
  }

  @Test
  public void rsaPkcs1() throws Exception {
    test(KeySpec.RSA2048, SignAlgo.RSA_SHA256);
  }

  @Test
  public void rsaPss() throws Exception {
    test(KeySpec.RSA2048, SignAlgo.RSAPSS_SHA256);
  }

  @Test
  public void ecdsa() throws Exception {
    test(KeySpec.P256, SignAlgo.ECDSA_SHA256);
  }

  @Test
  public void sm2() throws Exception {
    // the token does not return the public key of SM2 keys, it comes from the certificate.
    P11Slot slot = slot();
    String label = "signer-" + UUID.randomUUID();
    PKCS11KeyId keyId = slot.generateKeyPair(KeySpec.SM2, keySpec(label));
    try {
      PublicKey publicKey = slot.getPublicKey(keyId.getPublicKeyHandle());
      KeyPair issuerKp = KeyUtil.generateKeyPair(KeySpec.ED25519);
      Instant now = Instant.now();
      X509Cert cert = new X509Cert(new Certificate.V3CertBuilder(
          new X500Name("CN=issuer"), BigInteger.ONE, now, now.plus(1, ChronoUnit.DAYS),
          new X500Name("CN=SM2"), SubjectPublicKeyInfo.fromPublicKey(publicKey))
          .build(X509KeyUtil.getSigner(issuerKp.getPrivate(), issuerKp.getPublic()).contentSigner()));
      signAndVerify(label, SignAlgo.SM2_SM3, new X509Cert[]{cert});
    } finally {
      slot.destroyObjectsByIdLabel(null, label);
    }
  }

  @Test
  public void ed25519() throws Exception {
    test(KeySpec.ED25519, SignAlgo.ED25519);
  }

  @Test
  public void ed448() throws Exception {
    test(KeySpec.ED448, SignAlgo.ED448);
  }

  @Test
  public void mldsa44() throws Exception {
    test(KeySpec.MLDSA44, SignAlgo.MLDSA44);
  }

  @Test
  public void compositeMldsaEcdsa() throws Exception {
    testComposite(KeySpec.MLDSA44, KeySpec.P256, SignAlgo.MLDSA44_P256);
  }

  @Test
  public void compositeMldsaEd25519() throws Exception {
    testComposite(KeySpec.MLDSA44, KeySpec.ED25519, SignAlgo.MLDSA44_ED25519);
  }

  @Test
  public void hmac() throws Exception {
    byte[] keyValue = new byte[32];
    new SecureRandom().nextBytes(keyValue);

    P11Slot slot = slot();
    String label = "signer-" + UUID.randomUUID();
    slot.importSecretKey(keyValue, new PKCS11SecretKeySpec().token(true).label(label)
        .keyType(PKCS11T.CKK_GENERIC_SECRET).sign(true).verify(true));
    try {
      SignerConf conf = new SignerConf().setModule(MODULE).setSlot(0).setKeyLabel(label)
          .setAlgo(SignAlgo.HMAC_SHA256).setParallelism(1);

      P11SignerFactory factory = new P11SignerFactory();
      factory.setP11CryptServiceFactory(p11Factory);
      ConcurrentSigner concurrentSigner =
          factory.newSigner(new SecurityFactoryImpl(), "PKCS11", conf, null);
      Assert.assertTrue(concurrentSigner.isMac());
      Assert.assertEquals(SignAlgo.HMAC_SHA256, concurrentSigner.algorithm());

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(keyValue, "HmacSHA256"));
      byte[] expected = mac.doFinal(DATA);

      // atomic
      Assert.assertArrayEquals(expected, concurrentSigner.x509Sign(DATA));

      // streaming, twice to check that the state is reset
      Signer signer = concurrentSigner.borrowSigner();
      try {
        ContentSigner contentSigner = signer.contentSigner();
        for (int i = 0; i < 2; i++) {
          contentSigner.getOutputStream().write(DATA);
          Assert.assertArrayEquals("streaming " + i, expected, contentSigner.getSignature());
        }
      } finally {
        concurrentSigner.requiteSigner(signer);
      }
    } finally {
      slot.destroyObjectsByIdLabel(null, label);
    }
  }

  @Test
  public void mlkem() throws Exception {
    P11Slot slot = slot();
    String label = "signer-" + UUID.randomUUID();
    slot.generateKeyPair(KeySpec.MLKEM768,
        new PKCS11KeyPairSpec().token(true).label(label).decapsulate(true));
    try {
      kemSignAndVerify(label);
    } finally {
      slot.destroyObjectsByIdLabel(null, label);
    }
  }

  @Test
  public void compositeMlkem() throws Exception {
    P11Slot slot = slot();
    String core = "signer-" + UUID.randomUUID();
    String pqcLabel = P11CompositeKey.COMP_PQC_LABEL_PREFIX + core;
    String tradLabel = P11CompositeKey.COMP_TRAD_LABEL_PREFIX + core;
    slot.generateKeyPair(KeySpec.MLKEM768,
        new PKCS11KeyPairSpec().token(true).label(pqcLabel).decapsulate(true));
    slot.generateKeyPair(KeySpec.P256,
        new PKCS11KeyPairSpec().token(true).label(tradLabel).derive(true));
    try {
      kemSignAndVerify(P11CompositeKey.COMPOSITE_LABEL_PREFIX + core);
    } finally {
      slot.destroyObjectsByIdLabel(null, pqcLabel);
      slot.destroyObjectsByIdLabel(null, tradLabel);
    }
  }

  private static void kemSignAndVerify(String label) throws Exception {
    byte[] masterKeyValue = new byte[32];
    new SecureRandom().nextBytes(masterKeyValue);
    SecretKeyWithAlias masterKey = new SecretKeyWithAlias("mk-1",
        new SecretKeySpec(masterKeyValue, "HMAC-SHA256"));

    SecurityFactoryImpl securityFactory = new SecurityFactoryImpl() {
      @Override
      public CsrControl csrControl() {
        return new CsrControl() {
          @Override
          public KemEncapKey generateKemEncapKey(SubjectPublicKeyInfo publicKey)
              throws XiSecurityException {
            return KemUtil.generateKemEncapKey(publicKey, masterKey);
          }
        };
      }
    };

    SignerConf conf = new SignerConf().setModule(MODULE).setSlot(0).setKeyLabel(label)
        .setParallelism(1);
    P11SignerFactory factory = new P11SignerFactory();
    factory.setP11CryptServiceFactory(p11Factory);
    ConcurrentSigner concurrentSigner =
        factory.newSigner(securityFactory, "PKCS11", conf, null);

    SignAlgo algo = SignAlgo.KEM_HMAC_SHA256;
    Assert.assertEquals(algo, concurrentSigner.algorithm());

    ContentVerifierProvider cvp = X509KeyUtil.getContentVerifierProvider(
        concurrentSigner.publicKey(), null, masterKey.secretKey());

    Assert.assertTrue("atomic", cvp.get(algo.algorithmIdentifier())
        .atomicVerify(DATA, concurrentSigner.x509Sign(DATA)));

    byte[] otherData = DATA.clone();
    otherData[0] ^= 1;
    Assert.assertFalse("other data", cvp.get(algo.algorithmIdentifier())
        .atomicVerify(otherData, concurrentSigner.x509Sign(DATA)));

    Signer signer = concurrentSigner.borrowSigner();
    try {
      Assert.assertArrayEquals(algo.algorithmIdentifier().getEncoded(),
          signer.getEncodedX509AlgId());
      ContentSigner contentSigner = signer.contentSigner();
      Assert.assertEquals(algo.algorithmIdentifier(), contentSigner.getAlgorithmIdentifier());
      for (int i = 0; i < 2; i++) {
        contentSigner.getOutputStream().write(DATA);
        Assert.assertTrue("streaming " + i, cvp.get(algo.algorithmIdentifier())
            .atomicVerify(DATA, contentSigner.getSignature()));
      }
    } finally {
      concurrentSigner.requiteSigner(signer);
    }
  }

  private static P11Slot slot() throws Exception {
    P11Module module = p11Factory.getP11Module(MODULE);
    return module.getSlot(module.getSlotIdForIndex(0));
  }

  private static PKCS11KeyPairSpec keySpec(String label) {
    return new PKCS11KeyPairSpec().token(true).label(label).signVerify(true);
  }

  private static void test(KeySpec keySpec, SignAlgo algo) throws Exception {
    P11Slot slot = slot();
    String label = "signer-" + UUID.randomUUID();
    slot.generateKeyPair(keySpec, keySpec(label));
    try {
      signAndVerify(label, algo);
    } finally {
      slot.destroyObjectsByIdLabel(null, label);
    }
  }

  private static void testComposite(KeySpec pqc, KeySpec trad, SignAlgo algo) throws Exception {
    P11Slot slot = slot();
    String core = "signer-" + UUID.randomUUID();
    String pqcLabel = P11CompositeKey.COMP_PQC_LABEL_PREFIX + core;
    String tradLabel = P11CompositeKey.COMP_TRAD_LABEL_PREFIX + core;
    slot.generateKeyPair(pqc, keySpec(pqcLabel));
    slot.generateKeyPair(trad, keySpec(tradLabel));
    try {
      signAndVerify(P11CompositeKey.COMPOSITE_LABEL_PREFIX + core, algo);
    } finally {
      slot.destroyObjectsByIdLabel(null, pqcLabel);
      slot.destroyObjectsByIdLabel(null, tradLabel);
    }
  }

  private static void signAndVerify(String label, SignAlgo algo) throws Exception {
    signAndVerify(label, algo, null);
  }

  private static void signAndVerify(String label, SignAlgo algo, X509Cert[] chain)
      throws Exception {
    SignerConf conf = new SignerConf().setModule(MODULE).setSlot(0).setKeyLabel(label)
        .setAlgo(algo).setParallelism(1);

    P11SignerFactory factory = new P11SignerFactory();
    factory.setP11CryptServiceFactory(p11Factory);
    ConcurrentSigner concurrentSigner =
        factory.newSigner(new SecurityFactoryImpl(), "PKCS11", conf, chain);

    Assert.assertEquals(algo, concurrentSigner.algorithm());

    ContentVerifierProvider cvp =
        X509KeyUtil.getContentVerifierProvider(concurrentSigner.publicKey(), null, null);

    // atomic
    byte[] signature = concurrentSigner.x509Sign(DATA);
    Assert.assertTrue(algo + ": atomic signature",
        cvp.get(algo.algorithmIdentifier()).atomicVerify(DATA, signature));

    byte[] otherData = DATA.clone();
    otherData[0] ^= 1;
    Assert.assertFalse(algo + ": signature over other data",
        cvp.get(algo.algorithmIdentifier()).atomicVerify(otherData, signature));

    // streaming, twice to check that the state is reset
    Signer signer = concurrentSigner.borrowSigner();
    try {
      Assert.assertArrayEquals(algo.algorithmIdentifier().getEncoded(),
          signer.getEncodedX509AlgId());
      ContentSigner contentSigner = signer.contentSigner();
      Assert.assertEquals(algo.algorithmIdentifier(), contentSigner.getAlgorithmIdentifier());
      for (int i = 0; i < 2; i++) {
        contentSigner.getOutputStream().write(DATA);
        signature = contentSigner.getSignature();
        Assert.assertTrue(algo + ": streaming signature " + i,
            cvp.get(algo.algorithmIdentifier()).atomicVerify(DATA, signature));
      }
    } finally {
      concurrentSigner.requiteSigner(signer);
    }
  }

}
