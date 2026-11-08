// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs11.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.json.JsonParser;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactoryImpl;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.pkcs11.P11CryptServiceFactory;
import org.xipki.pkix.pkcs11.P11Module;
import org.xipki.pkix.pkcs11.P11SignerFactory;
import org.xipki.pkix.pkcs11.P11Slot;
import org.xipki.pkix.pkcs11.P11SystemConf;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.verify.XDHContentVerifierProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.UUID;

/**
 * DH POP (RFC 6955) with an X25519 / X448 key in a PKCS#11 token: P11SignerFactory computes the
 * shared secret with the static DH key of the CA in the token (CKM_ECDH1_DERIVE), and the CA
 * verifies the POP.
 *
 * @author Lijun Liao (xipki)
 */
public class P11DhPopSignerTest {

  private static final String MODULE = "default";

  private static final String PKCS11_CONF = "{\"modules\":[{"
      + "\"name\":\"" + MODULE + "\", \"readonly\":false, \"user\":\"CKU_USER\","
      + "\"numSessions\":4, \"includeSlots\":[{\"index\":0}],"
      + "\"nativeLibraries\":[{\"path\":\"xihsm:mem:vendor=xihsm\"}],"
      + "\"passwordSets\":[{\"passwords\":[\"123456\"]}]}]}";

  private static final byte[] DATA = "certificate request".getBytes(StandardCharsets.US_ASCII);

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
  public void testX25519() throws Exception {
    testDhPop(KeySpec.X25519, SignAlgo.DHPOP_X25519);
  }

  @Test
  public void testX448() throws Exception {
    testDhPop(KeySpec.X448, SignAlgo.DHPOP_X448);
  }

  private static void testDhPop(KeySpec keySpec, SignAlgo popAlgo) throws Exception {
    // the CA: a static DH key, certified by an Ed25519 key
    KeyPair issuerKp = KeyUtil.generateKeyPair(KeySpec.ED25519);
    KeyPair caDhKp = KeyUtil.generateKeyPair(keySpec);
    Instant now = Instant.now();
    X509Cert caDhCert = new X509Cert(new Certificate.V3CertBuilder(
        new X500Name("CN=DH POP issuer"), BigInteger.ONE, now, now.plus(1, ChronoUnit.DAYS),
        new X500Name("CN=DH POP " + keySpec),
        SubjectPublicKeyInfo.fromPublicKey(caDhKp.getPublic()))
        .build(KeyUtil.getSigner(issuerKp.getPrivate(), issuerKp.getPublic()).x509Signer()));

    // the requestor: the key in the token
    P11Module module = p11Factory.getP11Module(MODULE);
    P11Slot slot = module.getSlot(module.getSlotIdForIndex(0));
    String label = "dhpop-" + UUID.randomUUID();
    slot.generateKeyPair(keySpec, new PKCS11KeyPairSpec().token(true).label(label).derive(true));

    try {
      SignerConf conf = new SignerConf().setModule(MODULE).setSlot(0).setKeyLabel(label);
      conf.setPeerCertificates(Collections.singletonList(caDhCert));

      P11SignerFactory signerFactory = new P11SignerFactory();
      signerFactory.setP11CryptServiceFactory(p11Factory);
      ConcurrentSigner signer = signerFactory.newSigner(
          new SecurityFactoryImpl(), "PKCS11", conf, null);

      Assert.assertEquals(keySpec + ": POP algorithm", popAlgo, signer.algorithm());
      byte[] signature = signer.x509Sign(DATA);

      // the CA: verifies the POP
      ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(signer.publicKey(),
          new DHSigStaticKeyCertPair(caDhKp.getPrivate(), caDhCert), null);
      Assert.assertTrue(keySpec + ": verifier", cvp instanceof XDHContentVerifierProvider);
      Assert.assertTrue(keySpec + ": valid POP",
          cvp.get(popAlgo.algorithmIdentifier()).atomicVerify(DATA, signature));

      byte[] otherData = DATA.clone();
      otherData[0] ^= 1;
      Assert.assertFalse(keySpec + ": POP over other data",
          cvp.get(popAlgo.algorithmIdentifier()).atomicVerify(otherData, signature));
    } finally {
      slot.destroyObjectsByIdLabel(null, label);
    }
  }

}
