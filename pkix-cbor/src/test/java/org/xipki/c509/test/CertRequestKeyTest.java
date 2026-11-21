// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Test;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.c509.name.C509RdnAttribute;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.c509.registry.ConstRDNAttributeType;

import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Certification requests with all signing key types.
 *
 * @author Lijun Liao (xipki)
 */
public class CertRequestKeyTest {

  private static void request(String label, C509KeyPair key) throws Exception {
    Fixtures.request(key, new C509Name(
        new C509RdnAttribute(ConstRDNAttributeType.commonName, label),
        new C509RdnAttribute(ConstRDNAttributeType.organizationalUnit, "CSR key test")), null);
  }

  private static void request(int keyAlg) throws Exception {
    request(ConstPublicKeyAlgorithm.name(keyAlg), TestKeys.generate(keyAlg));
    if (ConstPublicKeyAlgorithm.isWeierstrass(keyAlg)) {
      request("compressed " + ConstPublicKeyAlgorithm.name(keyAlg),
              TestKeys.generate(keyAlg, true));
    }
  }

  @Test
  public void rsa() throws Exception {
    request("RSA, e=65537", TestKeys.generateRsa(2048, RSAKeyGenParameterSpec.F4));
    request("RSA, e=3", TestKeys.generateRsa(2048, RSAKeyGenParameterSpec.F0));
  }

  @Test
  public void ecdsa() throws Exception {
    for (int alg : new int[] {ConstPublicKeyAlgorithm.ec_secp256r1,
        ConstPublicKeyAlgorithm.ec_secp384r1, ConstPublicKeyAlgorithm.ec_secp521r1,
        ConstPublicKeyAlgorithm.ec_brainpoolP256r1, ConstPublicKeyAlgorithm.ec_brainpoolP384r1,
        ConstPublicKeyAlgorithm.ec_brainpoolP512r1, ConstPublicKeyAlgorithm.ec_sm2p256v1}) {
      request(alg);
    }
  }

  @Test
  public void edwards() throws Exception {
    request(ConstPublicKeyAlgorithm.ed25519);
    request(ConstPublicKeyAlgorithm.ed448);
  }

}
