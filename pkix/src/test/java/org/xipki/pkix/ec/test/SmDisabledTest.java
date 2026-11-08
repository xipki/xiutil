// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.ec.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.WeierstraussCurveEnum;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.util.misc.RandomUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;

/**
 * Tests that all other algorithms work if the SM algorithms are not available. Maven runs it in
 * its own JVM with the system property {@value KeyInfoUtil#PROP_DISABLE_SM} set to true. If it is
 * run alone (e.g. in the IDE or with -Dtest), the test sets the property itself.
 *
 * @author Lijun Liao (xipki)
 */
public class SmDisabledTest {

  private static final SecureRandom RND = RandomUtil.random();

  private static final boolean propertySetByTest;

  static {
    // The SM algorithms must be disabled before the crypto classes are initialized.
    // PROP_DISABLE_SM is a compile-time constant, using it does not initialize KeyUtil.
    propertySetByTest = !Boolean.getBoolean(KeyInfoUtil.PROP_DISABLE_SM);
    if (propertySetByTest) {
      System.setProperty(KeyInfoUtil.PROP_DISABLE_SM, "true");
    }
  }

  @BeforeClass
  public static void init() {
    Assert.assertFalse("SM2 was initialized before the SM algorithms were disabled. "
        + "Run this test in its own JVM, or with -D" + KeyInfoUtil.PROP_DISABLE_SM + "=true",
        WeierstraussCurveEnum.SM2.isSupported());
  }

  @AfterClass
  public static void cleanup() {
    if (propertySetByTest) {
      System.clearProperty(KeyInfoUtil.PROP_DISABLE_SM);
    }
  }

  @Test
  public void testSm2Unavailable() {
    Assert.assertFalse(WeierstraussCurveEnum.SM2.isSupported());
    try {
      WeierstraussCurveEnum.SM2.getOrder();
      Assert.fail("expected IllegalStateException");
    } catch (IllegalStateException e) {
      // expected
    }
  }

  @Test
  public void testOtherCurves() throws Exception {
    for (WeierstraussCurveEnum curve : WeierstraussCurveEnum.values()) {
      if (curve == WeierstraussCurveEnum.SM2) {
        continue;
      }

      Assert.assertTrue(curve.name(), curve.isSupported());
      BigInteger k = new BigInteger(curve.getOrder().bitLength() - 1, RND);
      ECPoint p = curve.multiplyBase(k);
      ECPoint decoded = curve.decodePoint(curve.encodePoint(p));
      Assert.assertEquals(curve.name(), p.getXCoordBigInt(), decoded.getXCoordBigInt());
    }
  }

  @Test
  public void testOtherKeyTypes() throws Exception {
    List<KeySpec> keySpecs = Arrays.asList(KeySpec.RSA2048, KeySpec.P256, KeySpec.ED25519,
        KeySpec.X25519, KeySpec.MLDSA65, KeySpec.MLKEM768, KeySpec.MLDSA65_P256,
        KeySpec.BRAINPOOLP256R1);

    for (KeySpec keySpec : keySpecs) {
      KeyPair kp = KeyUtil.generateKeyPair(keySpec);
      Assert.assertNotNull(keySpec.name(), kp.getPrivate());
    }

    KeyPair kp = KeyUtil.generateKeyPair(KeySpec.P256);
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(kp.getPrivate());
    sig.update(new byte[10]);
    byte[] sigValue = sig.sign();
    sig.initVerify(kp.getPublic());
    sig.update(new byte[10]);
    Assert.assertTrue(sig.verify(sigValue));
  }

}
