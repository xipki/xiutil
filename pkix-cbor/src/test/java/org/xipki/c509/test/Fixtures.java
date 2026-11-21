// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.cert.C509AkiMode;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.C509CertificateBuilder;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.ext.C509SubjectKeyIdentifier;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.csr.C509CertificationRequestBuilder;
import org.xipki.c509.sign.C509Signed;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * Builds test certificates and requests and checks that they survive an encode / decode round
 * trip and carry valid signatures.
 *
 * @author Lijun Liao (xipki)
 */
final class Fixtures {

  private static final SecureRandom RANDOM = new SecureRandom();

  private Fixtures() {
  }

  static byte[] bytes(int length, int value) {
    byte[] b = new byte[length];
    Arrays.fill(b, (byte) value);
    return b;
  }

  static byte[] sha256Prefix(byte[] data, int length) throws Exception {
    return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(data), length);
  }

  /**
   * A self-signed CA certificate with key usage keyCertSign and cRLSign.
   */
  static C509Certificate rootCa(C509KeyPair key, String subject) throws Exception {
    return issue(key, null, new C509Name(subject), key.subjectPublicKey(), null, b -> b
        .extension(C509Extension.critical(ConstExtensionId.basicConstraints,
            C509BasicConstraints.UNLIMITED_CA))
        .extension(C509Extension.critical(ConstExtensionId.keyUsage,
            C509KeyUsage.of(C509KeyUsage.CRL_SIGN, C509KeyUsage.KEY_CERT_SIGN))));
  }

  /**
   * Issues a certificate (self-signed if {@code issuerCert} is null), adds a subject key
   * identifier and checks the round trip and the signature.
   *
   * @param notAfter end of validity, null for one year.
   * @param tune     further settings of the builder, may be null.
   */
  static C509Certificate issue(
      C509KeyPair issuerKey, C509Certificate issuerCert, C509Name subject,
      C509SubjectPublicKey publicKey, Instant notAfter,
      Consumer<C509CertificateBuilder> tune) throws Exception {
    int sigAlg = TestKeys.signatureAlgorithmFor(issuerKey.subjectPublicKey().algorithm());
    return issue(sigAlg, issuerKey, issuerCert, subject, publicKey, notAfter, tune);
  }

  /**
   * Like the other issue method, but with an explicit signature algorithm.
   */
  static C509Certificate issue(
      int sigAlg, C509KeyPair issuerKey, C509Certificate issuerCert,
      C509Name subject, C509SubjectPublicKey publicKey, Instant notAfter,
      Consumer<C509CertificateBuilder> tune) throws Exception {
    Instant now = Instant.now();
    C509CertificateBuilder b = C509CertificateBuilder.of(subject, publicKey)
        .serialNumber(issuerCert == null ? BigInteger.ONE : new BigInteger(20 * 8, RANDOM))
        .validity(now, notAfter != null ? notAfter : now.plus(Duration.ofDays(365)))
        .issuedBy(issuerCert)
        .akiMode(issuerCert == null ? C509AkiMode.NONE : C509AkiMode.KEY_ID)
        .extension(C509Extension.nonCritical(ConstExtensionId.subjectKeyIdentifier,
            new C509SubjectKeyIdentifier(sha256Prefix(publicKey.getEncoded(), 20))));
    if (tune != null) {
      tune.accept(b);
    }

    C509Certificate cert = b.build(TestKeys.contentSigner(sigAlg, issuerKey.privateKey()));

    C509Certificate copy = roundTrip(cert, C509Certificate::read);
    PublicKey verifyKey = cert.isSelfSigned()
        ? TestKeys.toJca(cert.subjectPublicKey()) : issuerKey.publicKey();
    ContentVerifierFactory cvf = new TestKeys.MyContentVerifierFactory(verifyKey);

    Assert.assertTrue("signature of the certificate", cert.verify(cvf));
    Assert.assertTrue("signature of the decoded certificate", copy.verify(cvf));
    return cert;
  }

  /**
   * Builds, signs and checks a certification request.
   */
  static C509CertificationRequest request(
      C509KeyPair key, C509Name subject,
      Consumer<C509CertificationRequestBuilder> tune)
      throws Exception {
    C509CertificationRequestBuilder b =
        C509CertificationRequestBuilder.of(subject, key.subjectPublicKey());
    if (tune != null) {
      tune.accept(b);
    }
    int sigAlg = TestKeys.signatureAlgorithmFor(key.subjectPublicKey().algorithm());
    C509CertificationRequest csr = b.build(TestKeys.contentSigner(sigAlg, key.privateKey()));

    C509CertificationRequest copy = roundTrip(csr, C509CertificationRequest::read);
    for (C509CertificationRequest r : List.of(csr, copy)) {
      ContentVerifierFactory cvf = new TestKeys.MyContentVerifierFactory(
          TestKeys.toJca(r.body().subjectPublicKey()));
      Assert.assertTrue("proof of possession", r.verify(cvf));
    }
    return csr;
  }

  /**
   * Encodes, decodes and re-encodes the item and checks that nothing changes.
   */
  static <T extends C509CborItem> T roundTrip(
      T item,
      C509Cbor.Reader<T> reader) throws CodecException {
    byte[] encoded = item.getEncoded();
    T copy = C509Cbor.parse(encoded, reader);
    Assert.assertArrayEquals("re-encoded bytes", encoded, copy.getEncoded());
    Assert.assertEquals("decoded object", item, copy);
    Assert.assertFalse("text form", copy.toString().isEmpty());
    return copy;
  }

  /**
   * Verifies a signed structure and its decoded copy.
   */
  static <T extends C509Signed<?>> void assertSigned(
      T item, C509Cbor.Reader<T> reader, PublicKey key) throws Exception {
    T copy = roundTrip(item, reader);
    ContentVerifierFactory cvf = new TestKeys.MyContentVerifierFactory(key);
    Assert.assertTrue("signature", item.verify(cvf));
    Assert.assertTrue("signature of the copy", copy.verify(cvf));
  }

}
