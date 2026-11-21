// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.pkcs12.X509P12XdhMacSignerBuilder;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.sign.XDHContentVerifierFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Proof of possession of X25519 and X448 keys (DH POP, RFC 6955): the requestor MACs the request
 * with a key agreed with the static DH key of the CA, and the CA verifies it. Independent of the
 * names the crypto backend returns in Key.getAlgorithm() (the JDK returns "XDH").
 *
 * @author Lijun Liao (xipki)
 */
public class DhPopTest {

  private static final byte[] DATA = "certificate request".getBytes(StandardCharsets.US_ASCII);

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

    X500Name issuer = new X500Name("CN=DH POP issuer");
    Instant now = Instant.now();
    Certificate asn1Cert = new Certificate.V3CertBuilder(issuer, BigInteger.ONE,
        now, now.plus(1, ChronoUnit.DAYS), new X500Name("CN=DH POP " + keySpec),
        SubjectPublicKeyInfo.fromPublicKey(caDhKp.getPublic()))
        .build(KeyUtil.getSigner(issuerKp.getPrivate(), issuerKp.getPublic()).contentSigner());
    X509Cert caDhCert = new X509Cert(asn1Cert);

    // the requestor: MAC with the key agreed with the static DH key of the CA
    KeyPair kp = KeyUtil.generateKeyPair(keySpec);
    ConcurrentSigner signer = new X509P12XdhMacSignerBuilder(caDhCert, kp.getPrivate(),
        kp.getPublic()).createSigner(1);
    Assert.assertEquals(keySpec + ": POP algorithm", popAlgo, signer.algorithm());
    byte[] signature = signer.atomicX509Sign(DATA);

    // the CA: verifies the POP
    ContentVerifierFactory cvp = KeyUtil.getContentVerifierFactory(kp.getPublic(),
        new DHSigStaticKeyCertPair.X509(caDhKp.getPrivate(), caDhCert), null);
    Assert.assertTrue(keySpec + ": verifier " + cvp.getClass().getName(),
        cvp instanceof XDHContentVerifierFactory);

    Assert.assertTrue(keySpec + ": valid POP",
        cvp.get(popAlgo.algorithmIdentifier()).atomicX509Verify(DATA, signature));

    byte[] otherData = DATA.clone();
    otherData[0] ^= 1;
    Assert.assertFalse(keySpec + ": POP over other data",
        cvp.get(popAlgo.algorithmIdentifier()).atomicX509Verify(otherData, signature));
  }

}
