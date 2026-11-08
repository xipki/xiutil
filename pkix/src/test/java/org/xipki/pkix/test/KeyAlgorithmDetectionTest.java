// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.pkix.util.KeyUtil;

import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * Detection of the key type independent of the crypto backend: the names returned by
 * Key.getAlgorithm() differ, e.g. the JDK returns "EdDSA", "XDH", "ML-DSA" and "ML-KEM" where
 * BouncyCastle returns "Ed25519", "X25519", "ML-DSA-44" and "ML-KEM-768".
 *
 * @author Lijun Liao (xipki)
 */
public class KeyAlgorithmDetectionTest {

  @Test
  public void testGetCurve() throws Exception {
    assertCurve(KeySpec.P256, EcCurveEnum.P256);
    assertCurve(KeySpec.BRAINPOOLP256R1, EcCurveEnum.BRAINPOOLP256R1);
    assertCurve(KeySpec.ED25519, EcCurveEnum.ED25519);
    assertCurve(KeySpec.ED448, EcCurveEnum.ED448);
    assertCurve(KeySpec.X25519, EcCurveEnum.X25519);
    assertCurve(KeySpec.X448, EcCurveEnum.X448);
    assertCurve(KeySpec.RSA2048, null);
    assertCurve(KeySpec.MLDSA44, null);
    assertCurve(KeySpec.MLKEM768, null);
  }

  @Test
  public void testSignAlgoOfKey() throws Exception {
    assertSignAlgo(KeySpec.ED25519, SignAlgo.ED25519);
    assertSignAlgo(KeySpec.ED448, SignAlgo.ED448);
    assertSignAlgo(KeySpec.MLDSA44, SignAlgo.MLDSA44);
    assertSignAlgo(KeySpec.MLDSA65, SignAlgo.MLDSA65);
    assertSignAlgo(KeySpec.MLDSA87, SignAlgo.MLDSA87);
  }

  /**
   * The key type detection must not modify the encoding of the key: some providers return their
   * internal array in getEncoded(), e.g. the ML-KEM private key of BouncyCastle.
   */
  @Test
  public void testKeyEncodingUnchanged() throws Exception {
    KeySpec[] keySpecs = {KeySpec.RSA2048, KeySpec.P256, KeySpec.ED25519, KeySpec.X25519,
        KeySpec.X448, KeySpec.MLDSA44, KeySpec.MLKEM512, KeySpec.MLKEM768, KeySpec.MLKEM1024,
        KeySpec.MLKEM768_X25519, KeySpec.MLDSA44_ED25519};
    for (KeySpec keySpec : keySpecs) {
      for (Key key : keys(keySpec)) {
        byte[] encoded = key.getEncoded().clone();
        KeyInfoUtil.getCurve(key);
        KeyInfoUtil.getAlgorithmOid(key);
        try {
          SignAlgo.ofKey(key);
        } catch (NoSuchAlgorithmException e) {
          // e.g. KEM keys
        }
        Assert.assertArrayEquals(keySpec + " (" + key.getClass().getName() + ")",
            encoded, key.getEncoded());
      }
    }
  }

  private static void assertCurve(KeySpec keySpec, EcCurveEnum expected) throws Exception {
    for (Key key : keys(keySpec)) {
      Assert.assertEquals(keySpec + " (" + key.getAlgorithm() + ")", expected,
          KeyInfoUtil.getCurve(key));
    }
  }

  private static void assertSignAlgo(KeySpec keySpec, SignAlgo expected) throws Exception {
    for (Key key : keys(keySpec)) {
      Assert.assertEquals(keySpec + " (" + key.getAlgorithm() + ")", expected,
          SignAlgo.ofKey(key));
    }
  }

  /**
   * The generated keys, and the keys parsed from their encodings (as loaded from a keystore).
   */
  private static Key[] keys(KeySpec keySpec) throws Exception {
    KeyPair kp = KeyUtil.generateKeyPair(keySpec);
    return new Key[]{kp.getPublic(), kp.getPrivate(),
        KeyInfoUtil.getPublicKey(SubjectPublicKeyInfo.fromPublicKey(kp.getPublic())),
        KeyInfoUtil.getPrivateKey(PrivateKeyInfo.fromPrivateKey(kp.getPrivate()))};
  }

}
