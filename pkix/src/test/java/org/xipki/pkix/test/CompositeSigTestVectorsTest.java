// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPrivateKey;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509KeyUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.misc.RandomUtil;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Composite ML-DSA against the test vectors of draft-ietf-lamps-pq-composite-sigs-19,
 * Appendix E. The test vectors are from
 * https://github.com/lamps-wg/draft-composite-sigs, tag draft-ietf-lamps-pq-composite-sigs-19,
 * file src/testvectors.json (identical to the test vectors in the draft).
 * <p>
 * The signatures are randomized, the given signatures are verified, and new signatures are
 * computed with the given private keys and verified with the given public keys.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Parameterized.class)
public class CompositeSigTestVectorsTest {

  private static final String RESOURCE = "/composite-sigs/draft-19-testvectors.json";

  private static final SecureRandom RND = RandomUtil.random();

  private static final byte[] M;

  private static final byte[] CTX;

  private static final List<Object[]> TESTS = new ArrayList<>();

  private static final boolean MLDSA_CONTEXT_SUPPORTED;

  static {
    try (InputStream is = CompositeSigTestVectorsTest.class.getResourceAsStream(RESOURCE)) {
      JsonMap root = JsonParser.parseMap(is, false);
      M = root.getNnBytes("m");
      CTX = root.getNnBytes("ctx");
      JsonList tests = root.getList("tests");
      for (int i = 0; i < tests.size(); i++) {
        JsonMap t = (JsonMap) tests.getAt(i);
        TESTS.add(new Object[]{t.getNnString("tcId"), t});
      }
    } catch (Exception e) {
      throw new ExceptionInInitializerError(e);
    }

    MLDSA_CONTEXT_SUPPORTED = mldsaContextSupported();
  }

  private final String tcId;

  private final byte[] pk;

  private final byte[] x5c;

  private final byte[] sk;

  private final byte[] skPkcs8;

  private final byte[] s;

  private final byte[] sWithContext;

  public CompositeSigTestVectorsTest(String tcId, JsonMap test) throws Exception {
    this.tcId = tcId;
    this.pk = test.getNnBytes("pk");
    this.x5c = test.getNnBytes("x5c");
    this.sk = test.getNnBytes("sk");
    this.skPkcs8 = test.getNnBytes("sk_pkcs8");
    this.s = test.getNnBytes("s");
    this.sWithContext = test.getNnBytes("sWithContext");
  }

  @Parameterized.Parameters(name = "{0}")
  public static List<Object[]> tests() {
    return TESTS;
  }

  @Test
  public void testCountOfTestVectors() {
    Assert.assertEquals(21, TESTS.size());
  }

  /**
   * The composite signatures sign the ML-DSA component with a context (the label).
   */
  private static boolean mldsaContextSupported() {
    CryptoApi api = CryptoApiFactory.get();
    try {
      KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLDSA44);
      Signature sig = api.newSignature("ML-DSA-44");
      sig.initSign(kp.getPrivate());
      api.setContext(sig, new byte[]{1});
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean isComposite() {
    return !tcId.startsWith("id-ML-DSA-");
  }

  private X509Cert cert() throws Exception {
    return X509Util.parseCert(x5c);
  }

  /**
   * Public key: the certificate contains pk, and the parsed key has the same value.
   */
  @Test
  public void testPublicKey() throws Exception {
    assumeSuiteSupported();
    SubjectPublicKeyInfo spki = cert().subjectPublicKeyInfo();
    Assert.assertArrayEquals(tcId + ": pk in x5c", pk, spki.subjectPublicKey());

    PublicKey publicKey = KeyInfoUtil.getPublicKey(spki);
    if (isComposite()) {
      CompositeMLDSAPublicKey cpk = (CompositeMLDSAPublicKey) publicKey;
      Assert.assertEquals(tcId + ": suite", CompositeSigSuite.getAlgoSuite(spki.getAlgorithm()),
          cpk.suite());
      Assert.assertArrayEquals(tcId + ": keyValue", pk, cpk.keyValue());
    }
  }

  /**
   * Private key: sk_pkcs8 contains sk, and the parsed key is encoded the same.
   */
  @Test
  public void testPrivateKey() throws Exception {
    assumeSuiteSupported();
    PrivateKeyInfo skInfo = PrivateKeyInfo.fromEncoded(skPkcs8);
    Assert.assertEquals(tcId + ": algorithm of sk_pkcs8",
        cert().subjectPublicKeyInfo().getAlgorithm(), skInfo.getPrivateKeyAlgorithm());

    if (isComposite()) {
      Assert.assertArrayEquals(tcId + ": sk in sk_pkcs8", sk, skInfo.privateKey());

      CompositeMLDSAPrivateKey csk = (CompositeMLDSAPrivateKey) KeyInfoUtil.getPrivateKey(skInfo);
      Assert.assertArrayEquals(tcId + ": keyValue", sk, csk.keyValue());
      Assert.assertArrayEquals(tcId + ": getEncoded()", skPkcs8, csk.getEncoded());
    } else {
      // ML-DSA: sk is the seed, sk_pkcs8 the seed [0] choice of RFC 9881
      byte[] expected = XiArrays.concatenate(
          new byte[]{(byte) 0x80, (byte) sk.length}, sk);
      Assert.assertArrayEquals(tcId + ": sk in sk_pkcs8", expected, skInfo.privateKey());
      Assert.assertNotNull(KeyInfoUtil.getPrivateKey(skInfo));
    }
  }

  /**
   * The self-signed certificate x5c.
   */
  @Test
  public void testCertificate() throws Exception {
    assumeSuiteSupported();
    assumeContextIfComposite();
    X509Cert cert = cert();
    Assert.assertTrue(tcId + ": self-signed", cert.isSelfSigned());
    cert.verify(cert.publicKey());
  }

  /**
   * The given signature s over m with an empty ctx.
   */
  @Test
  public void testVerifySignature() throws Exception {
    assumeSuiteSupported();
    assumeContextIfComposite();
    PublicKey publicKey = cert().publicKey();
    Assert.assertTrue(tcId + ": s", verify(publicKey, null, s));
    Assert.assertFalse(tcId + ": s with ctx", verify(publicKey, CTX, s));
    Assert.assertFalse(tcId + ": s, first byte changed", verify(publicKey, null, flip(s, 0)));
    Assert.assertFalse(tcId + ": s, last byte changed",
        verify(publicKey, null, flip(s, s.length - 1)));

    if (isComposite()) {
      // the normal verification path, empty ctx
      SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(
          cert().subjectPublicKeyInfo().getAlgorithm());
      ContentVerifier verifier = X509KeyUtil.getContentVerifierProvider(publicKey)
          .get(signAlgo.algorithmIdentifier());
      Assert.assertTrue(tcId + ": s with ContentVerifier", verifier.atomicVerify(M, s));
    }
  }

  /**
   * The given signature sWithContext over m with ctx.
   */
  @Test
  public void testVerifySignatureWithContext() throws Exception {
    assumeSuiteSupported();
    Assume.assumeTrue("ML-DSA with context is not supported by the backend",
        MLDSA_CONTEXT_SUPPORTED);
    PublicKey publicKey = cert().publicKey();
    Assert.assertTrue(tcId + ": sWithContext", verify(publicKey, CTX, sWithContext));
    Assert.assertFalse(tcId + ": sWithContext, no ctx", verify(publicKey, null, sWithContext));
    Assert.assertFalse(tcId + ": sWithContext, first byte changed",
        verify(publicKey, CTX, flip(sWithContext, 0)));
  }

  /**
   * New signatures with sk, verified with pk.
   */
  @Test
  public void testSign() throws Exception {
    assumeSuiteSupported();
    assumeContextIfComposite();
    PrivateKey privateKey = KeyInfoUtil.getPrivateKey(PrivateKeyInfo.fromEncoded(skPkcs8));
    PublicKey publicKey = cert().publicKey();

    // the Signer of xipki, empty ctx
    byte[] sig = X509KeyUtil.getSigner(privateKey, publicKey).x509Sign(M);
    Assert.assertTrue(tcId + ": new signature", verify(publicKey, null, sig));

    if (MLDSA_CONTEXT_SUPPORTED) {
      sig = sign(privateKey, CTX);
      Assert.assertTrue(tcId + ": new signature with ctx", verify(publicKey, CTX, sig));
      Assert.assertFalse(tcId + ": new signature with ctx, no ctx", verify(publicKey, null, sig));
    }
  }

  /**
   * The suites with RSA PKCS#1 v1.5 are not supported by xipki (see CompositeSigSuite).
   */
  private void assumeSuiteSupported() throws Exception {
    if (isComposite()) {
      Assume.assumeTrue(tcId + " is not supported",
          CompositeSigSuite.getAlgoSuite(cert().subjectPublicKeyInfo().getAlgorithm()) != null);
    }
  }

  private void assumeContextIfComposite() {
    if (isComposite()) {
      Assume.assumeTrue("ML-DSA with context is not supported by the backend",
          MLDSA_CONTEXT_SUPPORTED);
    }
  }

  private static byte[] flip(byte[] data, int index) {
    byte[] ret = data.clone();
    ret[index] ^= 0x01;
    return ret;
  }

  /**
   * Verifies the signature over M; an invalid encoding counts as invalid signature.
   */
  private boolean verify(PublicKey publicKey, byte[] ctx, byte[] signature) throws Exception {
    byte[] context = ctx == null ? new byte[0] : ctx;
    try {
      if (publicKey instanceof CompositeMLDSAPublicKey) {
        CompositeMLDSAPublicKey cpk = (CompositeMLDSAPublicKey) publicKey;
        return CompositeSigUtil.verifyHash(cpk, context, cpk.suite().ph().hash(M), signature);
      }

      CryptoApi api = CryptoApiFactory.get();
      Signature sig = api.newSignature(SignAlgo.ofAlgorithmIdentifier(
          cert().subjectPublicKeyInfo().getAlgorithm()).jceName());
      sig.initVerify(publicKey);
      api.setContext(sig, context);
      sig.update(M);
      return sig.verify(signature);
    } catch (SignatureException e) {
      return false;
    }
  }

  /**
   * Signs M with ctx. The Signer of xipki supports only an empty ctx, the composite signature
   * is built from the components.
   */
  private byte[] sign(PrivateKey privateKey, byte[] ctx) throws Exception {
    CryptoApi api = CryptoApiFactory.get();
    if (!(privateKey instanceof CompositeMLDSAPrivateKey)) {
      Signature sig = api.newSignature(SignAlgo.ofKey(privateKey).jceName());
      sig.initSign(privateKey, RND);
      api.setContext(sig, ctx);
      sig.update(M);
      return sig.sign();
    }

    CompositeMLDSAPrivateKey csk = (CompositeMLDSAPrivateKey) privateKey;
    CompositeSigSuite suite = csk.suite();
    byte[] mPrime = CompositeSigUtil.buildM_(suite, ctx, suite.ph().hash(M));

    Signature sig = api.newSignature(suite.pqcVariant().signAlgo().jceName());
    KeyUtil.initSign(sig, csk.pqcKey());
    KeyInfoUtil.setContext(sig, suite.label());
    sig.update(mPrime);
    byte[] pqcSig = sig.sign();

    sig = api.newSignature(suite.tradVariant().signAlgo().jceName());
    KeyUtil.initSign(sig, csk.tradKey());
    sig.update(mPrime);
    byte[] tradSig = sig.sign();

    return XiArrays.concatenate(pqcSig, tradSig);
  }

  @Test
  public void testTestVectorComplete() {
    // guards against a truncated resource
    Assert.assertTrue(tcId, pk.length > 0 && sk.length > 0 && s.length > 0
        && sWithContext.length > 0 && !Arrays.equals(s, sWithContext));
  }

}
