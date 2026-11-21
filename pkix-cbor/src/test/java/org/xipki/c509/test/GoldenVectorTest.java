// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509Attributes;
import org.xipki.c509.attr.C509DateOfBirth;
import org.xipki.c509.attr.C509ChallengePassword;
import org.xipki.c509.attr.C509PrivateKeyPossessionStatement;
import org.xipki.c509.attr.C509TextAttrValue;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509ObjectId;
import org.xipki.c509.base.C509OtherName;
import org.xipki.c509.cert.C509AkiMode;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.C509CertificateBuilder;
import org.xipki.c509.crl.C509CertificateList;
import org.xipki.c509.crl.C509CRLBuilder;
import org.xipki.c509.crl.C509CRLInfoData;
import org.xipki.c509.crl.C509CRLInfo;
import org.xipki.c509.crl.C509PerIssuerRevokedCertsBuilder;
import org.xipki.c509.dump.C509Dumper;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509ASIdentifiers;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509CRLDistributionPoints;
import org.xipki.c509.ext.C509DistributionPointName;
import org.xipki.c509.ext.C509ExtKeyUsageSyntax;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509NullExtnValue;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509InfoAccess;
import org.xipki.c509.ext.C509AccessDescription;
import org.xipki.c509.ext.C509InhibitAnyPolicy;
import org.xipki.c509.ext.C509IPAddrBlocks;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.ext.C509NameConstraints;
import org.xipki.c509.ext.C509CertificatePolicies;
import org.xipki.c509.ext.C509PolicyQualifierInfo;
import org.xipki.c509.ext.C509PolicyConstraints;
import org.xipki.c509.ext.C509PolicyMappings;
import org.xipki.c509.ext.C509PreferredSignatureAlgorithm;
import org.xipki.c509.ext.C509SubjectDirectoryAttributes;
import org.xipki.c509.ext.C509SubjectKeyIdentifier;
import org.xipki.c509.ext.C509TLSFeatures;
import org.xipki.c509.ipres.C509ASIdOrRange;
import org.xipki.c509.ipres.C509IpBits;
import org.xipki.c509.ipres.C509IPAddressOrRange;
import org.xipki.c509.ipres.C509IPAddressFamily;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.ocsp.C509CertStatus;
import org.xipki.c509.ocsp.C509ErrorOCSPResponse;
import org.xipki.c509.ocsp.C509HashedId;
import org.xipki.c509.ocsp.C509Hasher;
import org.xipki.c509.ocsp.C509OCSPRequest;
import org.xipki.c509.ocsp.C509OCSPRequestBuilder;
import org.xipki.c509.ocsp.C509OCSPResponse;
import org.xipki.c509.ocsp.C509OCSPResponseBuilder;
import org.xipki.c509.ocsp.C509ResponseStatus;
import org.xipki.c509.ocsp.C509SimpleOCSPRequest;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.csrt.C509AlgorithmList;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.csr.C509CertificationRequestBuilder;
import org.xipki.c509.csrt.C509ExtensionsTemplate;
import org.xipki.c509.csrt.C509ExtensionTemplate;
import org.xipki.c509.csrt.C509NameTemplate;
import org.xipki.c509.csrt.C509RDNAttributeTemplate;
import org.xipki.c509.csrt.C509CertificationRequestTemplate;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.crypto.EmbedCertsMode;
import org.xipki.codec.Hex;
import org.xipki.codec.util.TripleState;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.C509ECSubjectPublicKey;
import org.xipki.c509.name.C509IssuerAndSerialNumber;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.c509.name.SpecialText;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.crypto.core.HashAlgo;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Checks that encoding is stable: every reference vector decodes and re-encodes to the same
 * bytes, and building the same content through the API yields the same bytes.
 *
 * @author Lijun Liao (xipki)
 */
public class GoldenVectorTest {

  private static final int HashedIdLength = 16;

  private static final int SerialNumLength = 16;

  private static final int NonceLength = 16;

  interface Parser {
    C509CborItem parse(byte[] encoded) throws CodecException;
  }

  private static final Instant T0 = Instant.ofEpochSecond(1700000000L);

  private static final C509ECSubjectPublicKey KEY = new C509ECSubjectPublicKey(
      ConstPublicKeyAlgorithm.ec_secp256r1,
      Hex.decode("02AE4CDB01F614DEFC7121285FDC7F5C6D1D42C95647F061BA0080DF678867845E"));

  private static byte[] fill(int n, int v) {
    byte[] b = new byte[n];
    Arrays.fill(b, (byte) v);
    return b;
  }

  private static C509ExtendedSigner fixedSigner(CoseC509 certs) {
    return new C509ExtendedSigner() {

      @Override
      public byte[] certHash(int c509HashAlg) {
        HashAlgo hashAlgo;
        try {
          hashAlgo = HashAlgo.getInstanceForC509Alg(c509HashAlg);
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return hashAlgo.hash(certs.first().getEncoded());
      }

      @Override
      public int c509Algorithm() {
        return ConstSignatureAlgorithm.ecdsa_with_SHA256;
      }

      @Override
      public SignatureValue c509Sign(byte[] tbs) {
        return new BytesSignatureValue(fill(64, 0x5A));
      }

      @Override
      public CoseC509 certificates() {
        return certs;
      }
    };
  }

  private static AtomicContentSigner fixedContentSigner() {
    return new AtomicContentSigner() {

      @Override
      public AlgorithmIdentifier x509Algorithm() {
        throw new UnsupportedOperationException("unsupported");
      }

      @Override
      public byte[] atomicX509Sign(byte[] dataToSign) throws SignatureException {
        throw new UnsupportedOperationException("unsupported");
      }

      @Override
      public int c509Algorithm() {
        return ConstSignatureAlgorithm.ecdsa_with_SHA256;
      }

      @Override
      public SignatureValue atomicC509Sign(byte[] dataToSign) throws SignatureException {
        return new BytesSignatureValue(fill(64, 0x5A));
      }

    };
  }

  private static Parser parserFor(String name) {
    if (name.startsWith("csrt")) {
      return C509CertificationRequestTemplate::parse;
    } else if (name.startsWith("csr")) {
      return C509CertificationRequest::parse;
    } else if (name.equals("crlInfo")) {
      return C509CRLInfo::parse;
    } else if (name.toLowerCase().contains("crl")) {
      return C509CertificateList::parse;
    } else if (name.endsWith("Req") || name.endsWith("Req2")) {
      return b -> (C509CborItem) C509OCSPRequest.parse(b);
    } else if (name.startsWith("ocsp")) {
      return b -> (C509CborItem) C509OCSPResponse.parse(b);
    } else {
      return C509Certificate::parse;
    }
  }

  @Test
  public void decodeAndReencode() throws Exception {
    for (Map.Entry<String, byte[]> e : GoldenVectors.all().entrySet()) {
      C509CborItem item = parserFor(e.getKey()).parse(e.getValue());
      Assert.assertEquals(e.getKey(), Hex.encode(e.getValue()), Hex.encode(item.getEncoded()));
      Assert.assertFalse(e.getKey(), item.toString().isEmpty());
    }
  }

  private static void assertGolden(String name, C509CborItem item) throws CodecException {
    System.out.println("is: " + Hex.encode(item.getEncoded())); // TODO
    System.out.println("ex: " + Hex.encode(GoldenVectors.get(name)));
    Assert.assertEquals(name, Hex.encode(GoldenVectors.get(name)),
        Hex.encode(item.getEncoded()));
  }

  static List<C509Extension> allExtensions() {
    C509GeneralNames names = C509GeneralNames.of(
        C509GeneralName.directory(new C509Name("C=DE,CN=Test")),
        C509GeneralName.dns("abc.com"),
        C509GeneralName.rfc822("abc@example.org"),
        C509GeneralName.smtpUtf8Mailbox("smtputf8@mailbox.org"),
        C509GeneralName.uri("http://myuri.com/abc"),
        C509GeneralName.registeredId(C509ObjectId.of("1.2.3.4")),
        C509GeneralName.ip(fill(4, 0x11)),
        C509GeneralName.macAddress(fill(6, 0x12)),
        C509GeneralName.otherName(new C509OtherName(C509ObjectId.of("1.2.3.4"), fill(10, 0x22))),
        C509GeneralName.hardwareModuleName(new C509OtherName(C509ObjectId.of("1.2.3.5"), fill(HashedIdLength,
            0x33))));

    C509IPAddressFamily v4 = new C509IPAddressFamily(C509IPAddressFamily.AFI_IPV4, null, List.of(
        C509IPAddressOrRange.prefix(new C509IpBits(0, new byte[] {10, 0})),
        C509IPAddressOrRange.range(new C509IpBits(0, new byte[] {10, 1}),
            new C509IpBits(4, new byte[] {10, 2, 0x10}))));
    C509IPAddressFamily v6 = new C509IPAddressFamily(C509IPAddressFamily.AFI_IPV6, null, List.of(
        C509IPAddressOrRange.prefix(new C509IpBits(0, fill(8, 0x20))),
        C509IPAddressOrRange.range(new C509IpBits(0, fill(9, 0x21)),
            new C509IpBits(1, fill(9, 0x22)))));

    return List.of(
        C509Extension.nonCritical(ConstExtensionId.subjectKeyIdentifier,
            new C509SubjectKeyIdentifier(fill(HashedIdLength, 1))),
        C509Extension.critical(ConstExtensionId.keyUsage,
            C509KeyUsage.of(C509KeyUsage.DIGITAL_SIGNATURE, C509KeyUsage.KEY_AGREEMENT)),
        C509Extension.nonCritical(ConstExtensionId.subjectAltName, new C509AltName(names)),
        C509Extension.critical(ConstExtensionId.basicConstraints, C509BasicConstraints.ca(1)),
        C509Extension.nonCritical(ConstExtensionId.cRLDistributionPoints,
            C509CRLDistributionPoints.of(
              C509DistributionPointName.of("http://crl1", "http://crl2"),
              new C509DistributionPointName(List.of("http://crl3"), 6,
                  new C509Name("CN=crl issuer")))),
        C509Extension.nonCritical(ConstExtensionId.freshestCRL,
            C509CRLDistributionPoints.of(C509DistributionPointName.of("http://delta"))),
        C509Extension.nonCritical(ConstExtensionId.certificatePolicies, C509CertificatePolicies.of(
            C509CertificatePolicies.Policy.of(3),
            C509CertificatePolicies.Policy.of(0, C509PolicyQualifierInfo.cps("http://cps"),
                C509PolicyQualifierInfo.userNotice("notice")))),
        C509Extension.nonCritical(ConstExtensionId.extKeyUsage, new C509ExtKeyUsageSyntax(1, 2, 9)),
        C509Extension.nonCritical(ConstExtensionId.authorityInfoAccess, C509InfoAccess.of(
            new C509AccessDescription(ConstAccessMethod.ocsp, "http://ocsp"),
            new C509AccessDescription(ConstAccessMethod.caIssuers, "http://ca"))),
        C509Extension.nonCritical(ConstExtensionId.subjectDirectoryAttributes,
            new C509SubjectDirectoryAttributes(C509Attributes.of(
                new C509Attribute(ConstAttributeType.dateOfBirth, new C509DateOfBirth(9000)),
                new C509Attribute(ConstAttributeType.gender, new C509TextAttrValue("F")),
                new C509Attribute(ConstAttributeType.countryOfResidence,
                    new C509TextAttrValue("DE"))))),
        C509Extension.nonCritical(ConstExtensionId.issuerAltName,
            C509AltName.of(C509GeneralName.dns("issuer.example"))),
        C509Extension.critical(ConstExtensionId.nameConstraints, new C509NameConstraints(
            C509GeneralNames.of(C509GeneralName.dns("permitted.dns"),
                C509GeneralName.ipSubnet(new byte[] {10, 0, 0, 0, (byte) 255, 0, 0, 0})),
            null)),
        C509Extension.nonCritical(ConstExtensionId.policyMappings, C509PolicyMappings.of(
            new C509PolicyMappings.Mapping(1, 2), new C509PolicyMappings.Mapping(3, 4))),
        C509Extension.critical(ConstExtensionId.policyConstraints,
            new C509PolicyConstraints(null, 2)),
        C509Extension.critical(ConstExtensionId.inhibitAnyPolicy, new C509InhibitAnyPolicy(5)),
        C509Extension.nonCritical(ConstExtensionId.subjectInfoAccess, C509InfoAccess.of(
            new C509AccessDescription(ConstAccessMethod.caRepository, "rsync://r"))),
        C509Extension.critical(ConstExtensionId.ipAddrBlocks, C509IPAddrBlocks.of(v6, v4)),
        C509Extension.critical(ConstExtensionId.autonomousSysIds, C509ASIdentifiers.of(
            C509ASIdOrRange.id(5), C509ASIdOrRange.range(10, 20), C509ASIdOrRange.id(30))),
        C509Extension.nonCritical(ConstExtensionId.ocsp_nocheck, C509NullExtnValue.INSTANCE),
        C509Extension.nonCritical(ConstExtensionId.tlsfeature, new C509TLSFeatures(5, 17)));
  }

  private static C509Certificate ca() throws Exception {
    return C509CertificateBuilder.of(new C509Name("C=DE,O=XiPKI,CN=Golden CA"), KEY)
        .serialNumber(BigInteger.ONE).validity(T0, null)
        .extension(ConstExtensionId.subjectKeyIdentifier, false,
            new C509SubjectKeyIdentifier(fill(HashedIdLength, 7)))
        .extension(ConstExtensionId.basicConstraints, true, C509BasicConstraints.UNLIMITED_CA)
        .extension(ConstExtensionId.keyUsage, true, C509KeyUsage.of(C509KeyUsage.KEY_CERT_SIGN,
            C509KeyUsage.CRL_SIGN))
        .extension(ConstExtensionId.subjectAltName, false,
            C509AltName.of(C509GeneralName.dns("ca.example")))
        .build(fixedContentSigner());
  }

  private static C509Certificate ee(C509Certificate ca) throws Exception {
    C509CertificateBuilder b = C509CertificateBuilder.of(new C509Name("CN=Golden EE"), KEY)
        .serialNumber(new BigInteger("123456789abcdef", 16))
        .validity(T0, T0.plusSeconds(86400 * 365))
        .issuedBy(ca).akiMode(C509AkiMode.ALL).issuerAltName(TripleState.optional);
    for (C509Extension e : allExtensions()) {
      if (e.id() != ConstExtensionId.issuerAltName) {
        b.extension(e);
      }
    }
    return b.build(fixedContentSigner());
  }

  @Test
  public void buildCertificates() throws Exception {
    C509Certificate ca = ca();
    assertGolden("ca", ca);
    assertGolden("ee", ee(ca));
    assertGolden("kuOnly", C509CertificateBuilder.of(new C509Name("CN=KU only"), KEY)
        .serialNumber(BigInteger.TEN).validity(T0, T0.plusSeconds(1000))
        .issuedBy(ca).akiMode(C509AkiMode.NONE)
        .extension(ConstExtensionId.keyUsage, false,
            C509KeyUsage.of(C509KeyUsage.DIGITAL_SIGNATURE))
        .build(fixedContentSigner()));
  }

  @Test
  public void buildRequests() throws Exception {
    C509CertificationRequestBuilder b = C509CertificationRequestBuilder
        .of(new C509Name("CN=Golden CSR"), KEY)
        .attribute(new C509Attribute(ConstAttributeType.challengePassword,
            new C509ChallengePassword("secret")))
        .attribute(new C509Attribute(ConstAttributeType.privateKeyPossessionStatement,
            new C509PrivateKeyPossessionStatement(new C509IssuerAndSerialNumber(
                new C509Name("CN=dummy"), BigInteger.ONE), fill(5, 0x44))));
    allExtensions().forEach(b::extension);
    C509CertificationRequest csr = b.build(fixedContentSigner());
    assertGolden("csr", csr);
    Assert.assertEquals("secret", csr.challengePassword());
    Assert.assertEquals(allExtensions().size(), csr.requestedExtensions().size());

    assertGolden("csr2", C509CertificationRequestBuilder.of(new C509Name(""), KEY)
        .attribute(new C509Attribute(ConstAttributeType.privateKeyPossessionStatement,
            new C509PrivateKeyPossessionStatement(new C509IssuerAndSerialNumber(
                new C509Name("CN=dummy"), BigInteger.TEN))))
        .build(fixedContentSigner()));

    assertGolden("csrt", new C509CertificationRequestTemplate(new int[] {2, 3},
        C509AlgorithmList.signatureAlgorithms(ConstSignatureAlgorithm.ecdsa_with_SHA256,
            ConstSignatureAlgorithm.ed25519),
        C509NameTemplate.of(
            C509RDNAttributeTemplate.fixed(ConstRDNAttributeType.country, "DE"),
            new C509RDNAttributeTemplate(ConstRDNAttributeType.organization, 0, 1,
                SpecialText.ofText("XiPKI")),
            C509RDNAttributeTemplate.free(ConstRDNAttributeType.commonName, 1, 1),
            new C509RDNAttributeTemplate(ConstRDNAttributeType.organizationalUnit, 1, 1,
                SpecialText.ofText("a,b"))),
        C509AlgorithmList.keyAlgorithms(ConstPublicKeyAlgorithm.ec_secp256r1,
            ConstPublicKeyAlgorithm.ed25519),
        C509ExtensionsTemplate.of(
            C509ExtensionTemplate.fixed(ConstExtensionId.keyUsage, false,
                C509KeyUsage.of(C509KeyUsage.DIGITAL_SIGNATURE)),
            C509ExtensionTemplate.open(ConstExtensionId.subjectAltName, true),
            C509ExtensionTemplate.fixed(ConstExtensionId.ocsp_nocheck, true,
                C509NullExtnValue.INSTANCE))));
    assertGolden("csrtEmpty", new C509CertificationRequestTemplate(null, null, null, null, null));
  }

  @Test
  public void buildCrls() throws Exception {
    C509Certificate ca = ca();
    C509CRLBuilder b = new C509CRLBuilder(7, ca, T0, T0.plusSeconds(3600));
    b.group(true, true, true)
        .revoked(BigInteger.valueOf(300), T0.minusSeconds(100), 1)
        .revoked(BigInteger.valueOf(2), T0.minusSeconds(5000), 0)
        .revoked(new BigInteger("1234567890", 16), T0.minusSeconds(10), 10)
        .expiredCertsOnCrl(T0.minusSeconds(86400));
    b.group(new C509Name("CN=Other CA"), false, true, true)
        .revoked(BigInteger.valueOf(65537), T0, 0)
        .revoked(BigInteger.valueOf(3), T0.minusSeconds(1), 2);
    C509CertificateList crl = b.build(fixedContentSigner());
    assertGolden("crl", crl);
    Assert.assertEquals(3, crl.body().groups().get(0).revoked().size());

    b = new C509CRLBuilder(8, ca, T0, null).deltaOf(7);
    C509PerIssuerRevokedCertsBuilder g = b.group(false, true, true);
    g.revoked(BigInteger.valueOf(99), T0.minusSeconds(60), 4)
        .removed(BigInteger.valueOf(98), T0.minusSeconds(30))
        .removed(BigInteger.valueOf(400), T0.minusSeconds(3000));
    assertGolden("deltaCrl", b.build(fixedContentSigner()));

    b = new C509CRLBuilder(9, ca, T0, T0.plusSeconds(60));
    b.group(false, true, true);
    assertGolden("emptyCrl", b.build(fixedContentSigner()));
    assertGolden("emptyCrl", new C509CRLBuilder(9, ca, T0, T0.plusSeconds(60))
        .build(fixedContentSigner()));

    assertGolden("crlInfo",
        new C509CRLInfo(new C509CRLInfoData(ConstSignatureAlgorithm.ecdsa_with_SHA256,
        C509NameVariant.ofC509(ca.subject()), fill(HashedIdLength, 7), 11, T0, T0.plusSeconds(7200), 10L,
        null)));
  }

  @Test
  public void buildOcsp() throws Exception {
    C509Certificate ca = ca();
    C509Certificate ee = ee(ca);
    C509ExtendedSigner signer = fixedSigner(CoseC509.of(ee, ca));

    assertGolden("ocspSimpleReq", new C509OCSPRequestBuilder(ConstHashAlgorithm.SHA256,
        HashedIdLength, fill(HashedIdLength, 0x0E)).buildSimple(ca, BigInteger.TEN, null));

    C509OCSPRequestBuilder qb = new C509OCSPRequestBuilder(ConstHashAlgorithm.SHA256,
        HashedIdLength, null)
        .acceptableResponseTypes(1, 2)
        .preferredSignatureAlgorithms(
            new C509PreferredSignatureAlgorithm(ConstSignatureAlgorithm.ecdsa_with_SHA256),
            new C509PreferredSignatureAlgorithm(ConstSignatureAlgorithm.ed25519,
                ConstPublicKeyAlgorithm.ed25519),
            new C509PreferredSignatureAlgorithm(
                ConstSignatureAlgorithm.sha256WithRSAEncryption,
                ConstPublicKeyAlgorithm.rsaEncryption, 1));
    qb.forIssuer(ca, null).query(BigInteger.valueOf(5))
        .query(BigInteger.valueOf(6),
            C509Extension.nonCritical(ConstExtensionId.ocsp_nocheck, C509NullExtnValue.INSTANCE));
    qb.forIssuer(new C509HashedId(fill(HashedIdLength, 9)), C509Extensions.of(
        C509Extension.nonCritical(ConstExtensionId.inhibitAnyPolicy, new C509InhibitAnyPolicy(1))))
        .query(new BigInteger(1, fill(SerialNumLength, 0x31)));
    assertGolden("ocspUnsignedReq", qb.buildUnsigned());

    qb = new C509OCSPRequestBuilder(ConstHashAlgorithm.SHA384, HashedIdLength, fill(8, 1));
    qb.forIssuer(ca, null).query(BigInteger.valueOf(77));
    assertGolden("ocspSignedReq", (C509CborItem) qb.buildSigned(signer, EmbedCertsMode.CHAIN));

    assertGolden("ocspSimpleReq2", new C509SimpleOCSPRequest(ConstHashAlgorithm.SHA256, null,
        new C509HashedId(fill(HashedIdLength, 3)), new BigInteger(1, fill(SerialNumLength, 4)),
        C509Extensions.of(
            C509Extension.nonCritical(ConstExtensionId.inhibitAnyPolicy,
                new C509InhibitAnyPolicy(0)))));

    assertGolden("ocspError", new C509ErrorOCSPResponse(C509ResponseStatus.tryLater));

    C509OCSPResponseBuilder rb = new C509OCSPResponseBuilder(ConstHashAlgorithm.SHA256, T0,
        fill(NonceLength, 0x0E)).acceptableResponseTypes(2);
    rb.forIssuer(new C509HashedId(fill(HashedIdLength, 2)), null)
        .answer(BigInteger.ONE, C509CertStatus.GOOD, T0.minusSeconds(10), T0.plusSeconds(3600))
        .answer(BigInteger.TEN, C509CertStatus.revoked(T0.minusSeconds(86400), 1),
                T0.minusSeconds(10), null)
        .answer(new BigInteger(1, fill(SerialNumLength, 5)), C509CertStatus.UNKNOWN, T0, null,
                C509Extension.nonCritical(ConstExtensionId.ocsp_nocheck,
                    C509NullExtnValue.INSTANCE));
    rb.forIssuer(new C509HashedId(fill(HashedIdLength, 3)), C509Extensions.EMPTY)
        .answer(BigInteger.valueOf(4), C509CertStatus.NOT_ISSUED, T0, T0);
    assertGolden("ocspBasicResp", rb.buildBasic(signer, EmbedCertsMode.CERT));

    C509HashedId eeId512 = new C509Hasher(ConstHashAlgorithm.SHA512, HashedIdLength)
                            .hashedIdForCert(ee);
    assertGolden("ocspSimpleResp", new C509OCSPResponseBuilder(ConstHashAlgorithm.SHA512, T0, null)
        .buildSimple(new C509HashedId(fill(HashedIdLength, 6)),
            new BigInteger(1, fill(SerialNumLength, 7)),
            C509CertStatus.revoked(T0, 4),
            T0.minusSeconds(5),
            T0.plusSeconds(500),
            signer, EmbedCertsMode.CHAIN, null));

    assertGolden("ocspSimpleResp2", new C509OCSPResponseBuilder(
        ConstHashAlgorithm.SHA256, T0, null)
        .buildSimple(new C509HashedId(fill(HashedIdLength, 6)),
            new BigInteger(1, fill(SerialNumLength, 7)),
            C509CertStatus.GOOD, T0, null, fixedSigner(CoseC509.of(ee)),
            EmbedCertsMode.NONE, null));
  }

  private static C509Dumper.Doc docFor(String name) {
    if (name.startsWith("csrt")) {
      return C509Dumper.Doc.REQUEST_TEMPLATE;
    } else if (name.startsWith("csr")) {
      return C509Dumper.Doc.CERT_REQUEST;
    } else if (name.toLowerCase().contains("crl")) {
      return C509Dumper.Doc.CRL;
    } else if (name.endsWith("Req") || name.endsWith("Req2")) {
      return C509Dumper.Doc.OCSP_REQUEST;
    } else if (name.startsWith("ocsp")) {
      return C509Dumper.Doc.OCSP_RESPONSE;
    } else {
      return C509Dumper.Doc.CERTIFICATE;
    }
  }

  @Test
  public void dumpAll() throws Exception {
    for (Map.Entry<String, byte[]> e : GoldenVectors.all().entrySet()) {
      if (e.getKey().equals("crlInfo")) {
        continue;
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      new C509Dumper(docFor(e.getKey()), e.getValue()).print(out);
      String text = out.toString(StandardCharsets.UTF_8);
      Assert.assertTrue(e.getKey(), text.length() > e.getValue().length);
    }
  }

  @Test
  public void equalityFollowsEncoding() throws Exception {
    Function<String, C509CborItem> parse = name -> {
      try {
        return parserFor(name).parse(GoldenVectors.get(name));
      } catch (CodecException e) {
        throw new IllegalStateException(e);
      }
    };
    for (String name : GoldenVectors.all().keySet()) {
      C509CborItem a = parse.apply(name);
      C509CborItem b = parse.apply(name);
      Assert.assertEquals(name, a, b);
      Assert.assertEquals(name, a.hashCode(), b.hashCode());
    }
    Assert.assertNotEquals(parse.apply("ca"), parse.apply("ee"));
  }

}
