// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.c509.name.C509RdnAttribute;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;

import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Self-signed certificates for all supported key types, and certificates for keys that
 * cannot sign (key agreement, key encapsulation).
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateKeyTest {

  private static C509Name name(String cn, String ou) {
    return new C509Name(new C509RdnAttribute(ConstRDNAttributeType.commonName, cn),
        new C509RdnAttribute(ConstRDNAttributeType.organizationalUnit, ou));
  }

  private static void selfSigned(String label, C509KeyPair key, int sigAlg) throws Exception {
    Fixtures.issue(sigAlg, key, null,
        name(label, ConstSignatureAlgorithm.name(sigAlg)), key.subjectPublicKey(), null,
        null);
  }

  private static void ecBothForms(int keyAlg) throws Exception {
    int sigAlg = TestKeys.signatureAlgorithmFor(keyAlg);
    for (boolean compressed : new boolean[] {false, true}) {
      selfSigned((compressed ? "compressed " : "uncompressed ")
          + ConstPublicKeyAlgorithm.name(keyAlg),
          TestKeys.generate(keyAlg, compressed), sigAlg);
    }
  }

  private static void keyWithoutSigning(int keyAlg, int caKeyAlg) throws Exception {
    C509KeyPair caKey = TestKeys.generate(caKeyAlg);
    String keyName = ConstPublicKeyAlgorithm.name(keyAlg);
    C509Certificate ca = Fixtures.issue(caKey, null, new C509Name("CN=" + keyName + " test CA"),
        caKey.subjectPublicKey(), null, null);
    Fixtures.issue(caKey, ca, new C509Name("CN=" + keyName),
        TestKeys.generate(keyAlg).subjectPublicKey(), null, null);
  }

  @Test
  public void rsa() throws Exception {
    C509KeyPair key = TestKeys.generateRsa(2048, RSAKeyGenParameterSpec.F4);
    selfSigned("RSA PKCS#1 v1.5", key, ConstSignatureAlgorithm.sha256WithRSAEncryption);
    selfSigned("RSA PSS", key, ConstSignatureAlgorithm.rsassa_pss_sha256);
    selfSigned("RSA with e=3", TestKeys.generateRsa(2048, RSAKeyGenParameterSpec.F0),
        ConstSignatureAlgorithm.sha256WithRSAEncryption);
  }

  @Test
  public void ecdsaNistCurves() throws Exception {
    ecBothForms(ConstPublicKeyAlgorithm.ec_secp256r1);
    ecBothForms(ConstPublicKeyAlgorithm.ec_secp384r1);
    ecBothForms(ConstPublicKeyAlgorithm.ec_secp521r1);
  }

  @Test
  public void ecdsaBrainpoolCurves() throws Exception {
    ecBothForms(ConstPublicKeyAlgorithm.ec_brainpoolP256r1);
    ecBothForms(ConstPublicKeyAlgorithm.ec_brainpoolP384r1);
    ecBothForms(ConstPublicKeyAlgorithm.ec_brainpoolP512r1);
  }

  @Test
  public void sm2() throws Exception {
    ecBothForms(ConstPublicKeyAlgorithm.ec_sm2p256v1);
  }

  @Test
  public void edwards() throws Exception {
    for (int alg : new int[] {ConstPublicKeyAlgorithm.ed25519, ConstPublicKeyAlgorithm.ed448}) {
      selfSigned(ConstPublicKeyAlgorithm.name(alg), TestKeys.generate(alg),
          TestKeys.signatureAlgorithmFor(alg));
    }
  }

  @Test
  public void mldsa() throws Exception {
    for (int alg : new int[] {ConstPublicKeyAlgorithm.ML_DSA_44,
        ConstPublicKeyAlgorithm.ML_DSA_65, ConstPublicKeyAlgorithm.ML_DSA_87}) {
      selfSigned(ConstPublicKeyAlgorithm.name(alg), TestKeys.generate(alg),
          TestKeys.signatureAlgorithmFor(alg));
    }
  }

  @Test
  public void keyAgreementKeys() throws Exception {
    keyWithoutSigning(ConstPublicKeyAlgorithm.x25519, ConstPublicKeyAlgorithm.ed25519);
    keyWithoutSigning(ConstPublicKeyAlgorithm.x448, ConstPublicKeyAlgorithm.ed448);
  }

  @Test
  public void kemKeys() throws Exception {
    keyWithoutSigning(ConstPublicKeyAlgorithm.ML_KEM_512, ConstPublicKeyAlgorithm.ML_DSA_44);
    keyWithoutSigning(ConstPublicKeyAlgorithm.ML_KEM_768, ConstPublicKeyAlgorithm.ML_DSA_65);
    keyWithoutSigning(ConstPublicKeyAlgorithm.ML_KEM_1024, ConstPublicKeyAlgorithm.ML_DSA_87);
  }

}
