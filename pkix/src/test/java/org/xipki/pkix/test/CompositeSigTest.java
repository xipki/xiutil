// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.Base64;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.X509KeyUtil;
import org.xipki.util.misc.RandomUtil;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * @author Lijun Liao (xipki)
 */
public class CompositeSigTest {

  static final byte[] m = Base64.decode(
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=");

  @Test
  public void test() throws Exception {
    // the composite signatures use the ML-DSA context, with the JDK backend only with the
    // JVM option --add-exports java.base/sun.security.provider=ALL-UNNAMED
    Assume.assumeTrue("ML-DSA context is not supported by the backend",
        mldsaContextSupported());
    SecureRandom rnd = RandomUtil.random();
    for (CompositeSigSuite suite : CompositeSigSuite.values()) {
      singleTest2(suite, rnd);
    }
  }

  private static boolean mldsaContextSupported() {
    try {
      KeyPair kp = KeyUtil.generateKeyPair(KeySpec.MLDSA44);
      Signature sig = CryptoApiFactory.get().newSignature("ML-DSA-44");
      sig.initSign(kp.getPrivate());
      CryptoApiFactory.get().setContext(sig, new byte[]{1});
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static void singleTest2(CompositeSigSuite suite, SecureRandom rnd)
      throws Exception {
    System.out.println("===== BEGIN testing " + suite + " =====");
    KeyPair kp = KeyUtil.generateKeyPair(suite.keySpec());

    SignAlgo signAlgo = SignAlgo.ofKey(kp.getPrivate());
    Assert.assertEquals(suite, signAlgo.compositeSigAlgoSuite());

    Signer signer = X509KeyUtil.getSigner(kp.getPrivate(), kp.getPublic());
    byte[] sigValue = signer.x509Sign(m);

    ContentVerifierProvider verifierProvider =
        X509KeyUtil.getContentVerifierProvider(kp.getPublic());
    ContentVerifier verifier = verifierProvider.get(signAlgo.algorithmIdentifier());
    boolean sigValid = verifier.atomicVerify(m, sigValue);
    Assert.assertTrue("message is not valid", sigValid);
  }

}
