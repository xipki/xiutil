// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.key.C509PEM;
import org.xipki.c509.key.C509PrivateKey;
import org.xipki.c509.registry.ConstPrivateKeyType;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.exception.CodecException;

import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;

/**
 * C509PrivateKey and C509PEM, and their conversion from and to the ASN.1 PrivateKeyInfo.
 *
 * @author Lijun Liao (xipki)
 */
public class PrivateKeyPemTest {

  private static final int[] KEY_ALGORITHMS = {
      ConstPublicKeyAlgorithm.rsaEncryption,
      ConstPublicKeyAlgorithm.ec_secp256r1,
      ConstPublicKeyAlgorithm.ec_secp384r1,
      ConstPublicKeyAlgorithm.ec_brainpoolP256r1,
      ConstPublicKeyAlgorithm.ed25519,
      ConstPublicKeyAlgorithm.ed448,
      ConstPublicKeyAlgorithm.x25519,
      ConstPublicKeyAlgorithm.ML_DSA_44,
      ConstPublicKeyAlgorithm.ML_KEM_768};

  @Test
  public void privateKeyInfoRoundTrip() throws Exception {
    for (int keyAlg : KEY_ALGORITHMS) {
      String label = ConstPublicKeyAlgorithm.describe(keyAlg);
      C509KeyPair key = keyAlg == ConstPublicKeyAlgorithm.rsaEncryption
          ? TestKeys.generateRsa(2048, RSAKeyGenParameterSpec.F4) : TestKeys.generate(keyAlg);
      PrivateKeyInfo pki = PrivateKeyInfo.fromPrivateKey(key.privateKey());

      boolean canSign = keyAlg != ConstPublicKeyAlgorithm.x25519
          && keyAlg != ConstPublicKeyAlgorithm.ML_KEM_768;
      CoseC509 certs = canSign ? CoseC509.of(Fixtures.rootCa(key, "CN=PEM test")) : null;

      C509PEM pem = Fixtures.roundTrip(C509PEM.fromPrivateKeyInfo(pki, certs), C509PEM::read);
      Assert.assertEquals(label, certs, pem.certificates());
      Assert.assertEquals(label, ConstPrivateKeyType.asymmetricKeyPackage,
          pem.privateKey().type());
      Assert.assertEquals(label, keyAlg, pem.privateKey().algorithm());
      Assert.assertTrue(label, pem.privateKey().toString().contains("******"));

      // the attributes and the public key of the PrivateKeyInfo are not kept.
      PrivateKeyInfo expected = new PrivateKeyInfo(pki.getPrivateKeyAlgorithm(),
          pki.privateKey());
      Assert.assertArrayEquals(label, expected.getEncoded(), pem.toPrivateKeyInfo().getEncoded());
    }
  }

  @Test
  public void withoutCertificates() throws Exception {
    C509PrivateKey key = C509PrivateKey.ofAsymmetricKeyPackage(
        ConstPublicKeyAlgorithm.ed25519,
        Fixtures.bytes(34, 0x11));
    C509PEM pem = Fixtures.roundTrip(new C509PEM(key, null), C509PEM::read);
    Assert.assertNull(pem.certificates());
    Assert.assertEquals(key, pem.privateKey());
  }

  @Test
  public void coseKey() throws Exception {
    // COSE_Key {1 (kty): 1 (OKP), -1 (crv): 6 (Ed25519), -4 (d): h'...'}
    C509PrivateKey key = C509PrivateKey.ofCoseKey(
        ConstPublicKeyAlgorithm.ed25519,
        Map.of(1L, 1L, -1L, 6L, -4L, Fixtures.bytes(32, 0x22)));
    C509PEM pem = Fixtures.roundTrip(new C509PEM(key, null), C509PEM::read);
    Assert.assertEquals(ConstPrivateKeyType.coseKey, pem.privateKey().type());
    Assert.assertThrows(CodecException.class, pem::toPrivateKeyInfo);
  }

}
