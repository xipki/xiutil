// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.pkix.sign.KemHmacSignature;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509KeyUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Tests the software signers: atomic and streaming signing, and that the state is reset.
 *
 * @author Lijun Liao (xipki)
 */
public class SoftwareSignerTest {

  private static final byte[] DATA = "data to be signed".getBytes(StandardCharsets.US_ASCII);

  private static final SecureRandom RND = new SecureRandom();

  @Test
  public void hmac() throws Exception {
    byte[] keyValue = new byte[32];
    RND.nextBytes(keyValue);

    Signer signer = new HmacSigner(SignAlgo.HMAC_SHA256,
        new SecretKeySpec(keyValue, "HMAC-SHA256"));
    assertAlgId(SignAlgo.HMAC_SHA256, signer);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(keyValue, "HmacSHA256"));
    byte[] expected = mac.doFinal(DATA);

    ContentSigner contentSigner = signer.x509Signer();
    Assert.assertArrayEquals(expected, contentSigner.atomicSign(DATA));
    Assert.assertArrayEquals(expected, signer.x509Sign(DATA));
    for (int i = 0; i < 2; i++) {
      contentSigner.getOutputStream().write(DATA);
      Assert.assertArrayEquals("streaming " + i, expected, contentSigner.getSignature());
    }
  }

  @Test
  public void kemHmac() throws Exception {
    byte[] macKey = new byte[32];
    RND.nextBytes(macKey);

    Signer signer = new KemHmacSigner("key-1", new SecretKeySpec(macKey, "HMAC-SHA256"));
    assertAlgId(SignAlgo.KEM_HMAC_SHA256, signer);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
    byte[] expected = new KemHmacSignature("key-1", mac.doFinal(DATA)).getEncoded();

    ContentSigner contentSigner = signer.x509Signer();
    Assert.assertArrayEquals(expected, contentSigner.atomicSign(DATA));
    for (int i = 0; i < 2; i++) {
      contentSigner.getOutputStream().write(DATA);
      Assert.assertArrayEquals("streaming " + i, expected, contentSigner.getSignature());
    }

    KemHmacSignature decoded = KemHmacSignature.decode(expected);
    Assert.assertEquals("key-1", decoded.id());
  }

  @Test
  public void kemHmacPop() throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLKEM768);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromPublicKey(kp.getPublic());
    byte[] masterKeyValue = new byte[32];
    RND.nextBytes(masterKeyValue);
    SecretKeyWithAlias masterKey = new SecretKeyWithAlias("mk-1",
        new SecretKeySpec(masterKeyValue, "HMAC-SHA256"));
    KemEncapKey encapKey = KemUtil.generateKemEncapKey(spki, masterKey);

    byte[] macKey = KemUtil.mlkemDecryptSecret(kp.getPrivate(), encapKey.encapulation());
    ContentSigner signer = new KemHmacSigner(encapKey.id(),
        new SecretKeySpec(macKey, "HMAC-SHA256")).x509Signer();

    ContentVerifierProvider cvp =
        X509KeyUtil.getContentVerifierProvider(kp.getPublic(), null, masterKey.secretKey());
    Assert.assertTrue(cvp.get(SignAlgo.KEM_HMAC_SHA256.algorithmIdentifier())
        .atomicVerify(DATA, signer.atomicSign(DATA)));
  }

  @Test
  public void signatureEcdsa() throws Exception {
    testSignature(KeySpec.P256, SignAlgo.ECDSA_SHA256, "SHA256withECDSA");
  }

  @Test
  public void signatureRsa() throws Exception {
    testSignature(KeySpec.RSA2048, SignAlgo.RSA_SHA256, "SHA256withRSA");
  }

  @Test
  public void signatureEd25519() throws Exception {
    testSignature(KeySpec.ED25519, SignAlgo.ED25519, "Ed25519");
  }

  private static void testSignature(KeySpec keySpec, SignAlgo algo, String jdkName)
      throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(keySpec);
    Signer signer = new SignatureSigner(algo, Signature.getInstance(jdkName),
        kp.getPrivate(), null);
    assertAlgId(algo, signer);

    ContentSigner[] contentSigners = {signer.x509Signer(),
        SignatureSigner.newContentSigner(algo, kp.getPrivate())};
    for (ContentSigner contentSigner : contentSigners) {
      Assert.assertTrue("atomic", verify(jdkName, kp, DATA, contentSigner.atomicSign(DATA)));

      for (int i = 0; i < 2; i++) {
        contentSigner.getOutputStream().write(DATA);
        Assert.assertTrue("streaming " + i,
            verify(jdkName, kp, DATA, contentSigner.getSignature()));
      }

      byte[] otherData = DATA.clone();
      otherData[0] ^= 1;
      Assert.assertFalse("other data",
          verify(jdkName, kp, otherData, contentSigner.atomicSign(DATA)));
    }
  }

  private static boolean verify(String jdkName, KeyPair kp, byte[] data, byte[] signature)
      throws Exception {
    Signature verifier = Signature.getInstance(jdkName);
    verifier.initVerify(kp.getPublic());
    verifier.update(data);
    return verifier.verify(signature);
  }

  private static void assertAlgId(SignAlgo algo, Signer signer) {
    Assert.assertArrayEquals(algo.algorithmIdentifier().getEncoded(),
        signer.getEncodedX509AlgId());
    Assert.assertEquals(algo.algorithmIdentifier(),
        signer.x509Signer().getAlgorithmIdentifier());
  }

}
