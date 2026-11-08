// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemEncapsulation;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509KeyUtil;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.pkix.verify.KEMContentVerifierProvider;
import org.xipki.util.misc.RandomUtil;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * Proof of possession of KEM keys (KEM-HMAC-SHA256), and the selection of the verifier by the
 * key type, independent of the names the crypto backend returns in PublicKey.getAlgorithm()
 * (e.g. the JDK: "ML-KEM" for all parameter sets, "XDH" for X25519 and X448).
 *
 * @author Lijun Liao (xipki)
 */
public class KemPopTest {

  private static final SecureRandom RND = RandomUtil.random();

  private static final byte[] DATA = "certificate request".getBytes(StandardCharsets.US_ASCII);

  @Test
  public void testMlkem512() throws Exception {
    testKemPop(KeySpec.MLKEM512);
  }

  @Test
  public void testMlkem768() throws Exception {
    testKemPop(KeySpec.MLKEM768);
  }

  @Test
  public void testMlkem1024() throws Exception {
    testKemPop(KeySpec.MLKEM1024);
  }

  @Test
  public void testCompositeMlkem768X25519() throws Exception {
    testKemPop(KeySpec.MLKEM768_X25519);
  }

  @Test
  public void testCompositeMlkem1024X448() throws Exception {
    testKemPop(KeySpec.MLKEM1024_X448);
  }

  /**
   * The RSA-OAEP variants: the traditional private key is the RSAPrivateKey.
   */
  @Test
  public void testCompositeMlkemRsa() throws Exception {
    KeySpec[] keySpecs = {KeySpec.MLKEM768_RSA2048, KeySpec.MLKEM768_RSA3072,
        KeySpec.MLKEM768_RSA4096, KeySpec.MLKEM1024_RSA3072};
    for (KeySpec keySpec : keySpecs) {
      testKemPop(keySpec);
    }
  }

  /**
   * The ECDH variants: the encapsulation and the decapsulation must agree on the shared
   * secret (the x coordinate of the fixed-length point encoding).
   */
  @Test
  public void testCompositeMlkemEcdh() throws Exception {
    KeySpec[] keySpecs = {KeySpec.MLKEM768_P256, KeySpec.MLKEM768_P384, KeySpec.MLKEM768_BP256,
        KeySpec.MLKEM1024_P384, KeySpec.MLKEM1024_BP384, KeySpec.MLKEM1024_P521};
    for (KeySpec keySpec : keySpecs) {
      for (int i = 0; i < 3; i++) {
        testKemPop(keySpec);
      }
    }
  }

  /**
   * X25519 keys are verified with the XDH verifier, which needs the owner key and certificate.
   */
  @Test
  public void testXdhVerifierIsSelected() throws Exception {
    for (KeySpec keySpec : new KeySpec[]{KeySpec.X25519, KeySpec.X448}) {
      KeyPair kp = KeyUtil.generateKeyPair(keySpec);
      try {
        X509KeyUtil.getContentVerifierProvider(kp.getPublic(), null, null);
        Assert.fail(keySpec + ": InvalidKeyException expected");
      } catch (InvalidKeyException e) {
        Assert.assertTrue(keySpec + ": " + e.getMessage(),
            e.getMessage().contains("ownerKeyAndCert"));
      }
    }
  }

  private static void testKemPop(KeySpec keySpec) throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(keySpec);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromPublicKey(kp.getPublic());

    byte[] masterKeyValue = new byte[32];
    RND.nextBytes(masterKeyValue);
    SecretKeyWithAlias masterKey = new SecretKeyWithAlias("mk-1",
        new SecretKeySpec(masterKeyValue, "HMAC-SHA256"));

    // CA: encapsulates the MAC key to the public key
    KemEncapKey encapKey = KemUtil.generateKemEncapKey(spki, masterKey);

    // requestor: decapsulates the MAC key with the private key, and MACs the request
    byte[] macKey;
    if (encapKey.encapulation().alg() == KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC) {
      macKey = KemUtil.compositeMlKemDecryptSecret(kp.getPrivate(), spki.subjectPublicKey(),
          encapKey.encapulation());
    } else {
      macKey = KemUtil.mlkemDecryptSecret(kp.getPrivate(), encapKey.encapulation());
    }

    ContentSigner signer = new KemHmacSigner(encapKey.id(),
        new SecretKeySpec(macKey, "HMAC-SHA256")).contentSigner();
    byte[] signature = signer.atomicSign(DATA);

    // CA: verifies the POP
    ContentVerifierProvider cvp =
        X509KeyUtil.getContentVerifierProvider(kp.getPublic(), null, masterKey.secretKey());
    Assert.assertTrue(keySpec + ": verifier " + cvp.getClass().getName(),
        cvp instanceof KEMContentVerifierProvider);

    Assert.assertTrue(keySpec + ": valid POP", cvp.get(SignAlgo.KEM_HMAC_SHA256
        .algorithmIdentifier()).atomicVerify(DATA, signature));

    byte[] otherData = DATA.clone();
    otherData[0] ^= 1;
    Assert.assertFalse(keySpec + ": POP over other data", cvp.get(SignAlgo.KEM_HMAC_SHA256
        .algorithmIdentifier()).atomicVerify(otherData, signature));
  }

}
