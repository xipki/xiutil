// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.C509CertificateBuilder;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.crl.C509CertificateList;
import org.xipki.c509.crl.C509CRLBuilder;
import org.xipki.c509.crl.C509CRLInfo;
import org.xipki.c509.crl.C509CRLInfoData;
import org.xipki.c509.crl.C509PerIssuerRevokedCerts;
import org.xipki.c509.crl.C509RevocationReason;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.ext.C509RawExtnValue;
import org.xipki.c509.ext.C509SubjectKeyIdentifier;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.ocsp.C509BasicOCSPResponse;
import org.xipki.c509.ocsp.C509CertStatus;
import org.xipki.c509.ocsp.C509HashedId;
import org.xipki.c509.ocsp.C509Hasher;
import org.xipki.c509.ocsp.C509OCSPRequestBuilder;
import org.xipki.c509.ocsp.C509OCSPResponse;
import org.xipki.c509.ocsp.C509OCSPResponseBuilder;
import org.xipki.c509.ocsp.C509BasicOCSPRequest;
import org.xipki.c509.ocsp.C509SimpleOCSPResponse;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.crypto.EmbedCertsMode;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * CRLs and OCSP messages signed with real keys.
 *
 * @author Lijun Liao (xipki)
 */
public class RevocationAndStatusTest {

  private static final int HASHED_ID_LEN = 16;

  private static final int NONCE_LEN = 16;

  private static C509KeyPair caKey;

  private static C509Certificate ca;

  private static C509KeyPair responderKey;

  private static C509Certificate responder;

  @BeforeClass
  public static void setup() throws Exception {
    caKey = TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1);
    ca = Fixtures.rootCa(caKey, "C=DE, CN=Status Test CA");
    responderKey = TestKeys.generate(ConstPublicKeyAlgorithm.ed25519);
    responder = Fixtures.issue(caKey, ca, new C509Name("CN=OCSP responder"),
        responderKey.subjectPublicKey(), null, b -> b.extension(
            C509Extension.critical(ConstExtensionId.keyUsage,
                C509KeyUsage.of(C509KeyUsage.DIGITAL_SIGNATURE))));
  }

  private static AtomicContentSigner caSigner() {
    return TestKeys.contentSigner(
        TestKeys.signatureAlgorithmFor(ConstPublicKeyAlgorithm.ec_secp256r1),
        caKey.privateKey());
  }

  private static C509ExtendedSigner responderSigner() {
    return TestKeys.signer(TestKeys.signatureAlgorithmFor(ConstPublicKeyAlgorithm.ed25519),
        responderKey.privateKey(), CoseC509.of(responder, ca));
  }

  @Test
  public void fullCrl() throws Exception {
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    C509CRLBuilder b = new C509CRLBuilder(1, ca, now, now.plus(1, ChronoUnit.DAYS));
    b.group(true, true, true)
        .revoked(BigInteger.valueOf(1000), now.minusSeconds(7200), 1)
        .revoked(BigInteger.valueOf(17), now.minusSeconds(70000), 4);
    b.group(new C509Name("CN=Other CA"), false, false, false)
        .revoked(BigInteger.valueOf(5), (Long) null, 0)
        .revoked(new BigInteger("123456789abcdef0", 16), (Long) null, 0);
    C509CertificateList crl = b.build(caSigner());
    Fixtures.assertSigned(crl, C509CertificateList::read, caKey.publicKey());

    List<C509PerIssuerRevokedCerts> groups = crl.body().groups();
    Assert.assertEquals(2, groups.size());
    C509PerIssuerRevokedCerts.Entry first = groups.get(0).revoked().get(0);
    Assert.assertEquals(BigInteger.valueOf(17), first.serialNumber());
    Assert.assertEquals(Long.valueOf(now.minusSeconds(70000).getEpochSecond()), first.date());
    Assert.assertEquals(Integer.valueOf(C509RevocationReason.SUPERSEDED.code()), first.reason());

    C509PerIssuerRevokedCerts.Entry other = groups.get(1).revoked().get(1);
    Assert.assertEquals(new BigInteger("123456789abcdef0", 16), other.serialNumber());
    Assert.assertNull(other.date());
    Assert.assertNull(other.reason());
  }

  @Test
  public void deltaCrlWithReasonsButNoDates() throws Exception {
    Instant now = Instant.now();
    C509CRLBuilder b = new C509CRLBuilder(3, ca, now, null).deltaOf(2);
    b.group(false, false, true)
        .revoked(BigInteger.TEN, (Long) null, C509RevocationReason.KEY_COMPROMISE.code())
        .removed(BigInteger.ONE, (Long) null);
    C509CertificateList crl = b.build(caSigner());
    Fixtures.assertSigned(crl, C509CertificateList::read, caKey.publicKey());
    C509PerIssuerRevokedCerts g = crl.body().groups().get(0);
    Assert.assertEquals(Integer.valueOf(1), g.revoked().get(0).reason());
    Assert.assertEquals(BigInteger.ONE, g.removed().get(0).serialNumber());
    Assert.assertEquals(Long.valueOf(2), crl.header().baseCrlNumber());
  }

  @Test
  public void signedOcspRequest() throws Exception {
    C509OCSPRequestBuilder b = new C509OCSPRequestBuilder(
        ConstHashAlgorithm.SHA256, HASHED_ID_LEN, Fixtures.bytes(NONCE_LEN, 7));
    b.forIssuer(ca, null).query(BigInteger.valueOf(3)).query(BigInteger.valueOf(4));
    C509BasicOCSPRequest request = b.buildSigned(responderSigner(), EmbedCertsMode.CHAIN);

    ContentVerifierFactory cvf = new TestKeys.MyContentVerifierFactory(responderKey.publicKey());
    Assert.assertTrue("signature", request.verify(cvf));

    Assert.assertNotNull(request.requestorCerts());
    Assert.assertEquals(1, request.requestorCerts().c509().size());
  }

  @Test
  public void ocspResponses() throws Exception {
    C509Hasher hasher = new C509Hasher(ConstHashAlgorithm.SHA256, HASHED_ID_LEN);
    C509HashedId caHash = hasher.hashedIdForCert(ca);
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    C509OCSPResponseBuilder b = new C509OCSPResponseBuilder(ConstHashAlgorithm.SHA256, now, null);
    b.forIssuer(caHash, null)
        .answer(BigInteger.ONE, C509CertStatus.GOOD, now, now.plusSeconds(600))
        .answer(BigInteger.TEN, C509CertStatus.revoked(now.minusSeconds(60), 1), now, null);
    C509BasicOCSPResponse basic = b.buildBasic(responderSigner(), EmbedCertsMode.CERT);
    Fixtures.assertSigned(basic, in -> (C509BasicOCSPResponse) C509OCSPResponse.read(in),
        responderKey.publicKey());
    Assert.assertEquals(C509CertStatus.Kind.REVOKED,
        basic.body().responses().get(0).answers().get(1).status().kind());

    C509SimpleOCSPResponse simple =
        new C509OCSPResponseBuilder(ConstHashAlgorithm.SHA256, now, null)
        .buildSimple(caHash, BigInteger.TWO, C509CertStatus.UNKNOWN, now, null,
            responderSigner(), EmbedCertsMode.NONE, null);
    Fixtures.assertSigned(simple, in -> (C509SimpleOCSPResponse) C509OCSPResponse.read(in),
        responderKey.publicKey());
    Assert.assertNull(simple.body().responderCerts());
  }

  @Test(expected = IllegalArgumentException.class)
  public void crlIssuerNeedsCrlSign() throws Exception {
    new C509CRLBuilder(1, responder, Instant.now(), null);
  }

  /** The CRL field authorityKeyIdentifier is mandatory: the CA needs a subject key identifier. */
  @Test(expected = IllegalArgumentException.class)
  public void crlIssuerNeedsSubjectKeyId() throws Exception {
    C509Certificate noSki = C509CertificateBuilder
        .of(new C509Name("CN=CA without SKI"), caKey.subjectPublicKey())
        .extension(C509Extension.critical(ConstExtensionId.keyUsage,
            C509KeyUsage.of(C509KeyUsage.CRL_SIGN, C509KeyUsage.KEY_CERT_SIGN)))
        .build(caSigner());
    new C509CRLBuilder(1, noSki, Instant.now(), null);
  }

  @Test
  public void crlAuthorityKeyIdMandatory() throws Exception {
    Instant now = Instant.now();
    int sigAlg = ConstSignatureAlgorithm.ecdsa_with_SHA256;
    Assert.assertThrows(NullPointerException.class, () -> new C509CRLInfoData(
        sigAlg, C509NameVariant.ofC509(ca.subject()), null, 1, now, null, null, null));
    Assert.assertThrows(IllegalArgumentException.class, () -> new C509CRLInfoData(
        sigAlg, C509NameVariant.ofC509(ca.subject()), new byte[0], 1, now, null, null, null));

    // [0, 0, [4, "a"], h'01', 1, 0, null, null, []]
    C509CRLInfo.parse(Hex.decode("89000082046161410101" + "00f6f680"));
    // [0, 0, [4, "a"], null, 1, 0, null, null, []]
    Assert.assertThrows(CodecException.class,
        () -> C509CRLInfo.parse(Hex.decode("890000820461" + "61f60100f6f680")));
  }

  @Test(expected = IllegalStateException.class)
  public void issuerWithoutSubjectKeyIdRejected() throws Exception {
    C509Certificate noSki = C509CertificateBuilder
        .of(new C509Name("CN=no SKI"), caKey.subjectPublicKey())
        .build(caSigner());
    C509CertificateBuilder.of(new C509Name("CN=child"),
        responderKey.subjectPublicKey()).issuedBy(noSki).build(caSigner());
  }

  @Test
  public void foreignValueClassIsConverted() {
    C509Extension e = new C509Extension(ConstExtensionId.subjectKeyIdentifier, false,
        new C509RawExtnValue(new byte[] {1, 2, 3}));
    Assert.assertEquals(C509SubjectKeyIdentifier.class, e.value().getClass());
  }

}
