// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.asn1.cmp.CertResponse;
import org.xipki.asn1.cmp.CertifiedKeyPair;
import org.xipki.asn1.cmp.Challenge;
import org.xipki.asn1.cmp.ErrorMsgContent;
import org.xipki.asn1.cmp.PBMParameter;
import org.xipki.asn1.cmp.PKIBody;
import org.xipki.asn1.cmp.PKIFreeText;
import org.xipki.asn1.cmp.PKIHeader;
import org.xipki.asn1.cmp.PKIStatus;
import org.xipki.asn1.cmp.PKIStatusInfo;
import org.xipki.asn1.cms.SignedData;
import org.xipki.asn1.crmf.EncKeyWithID;
import org.xipki.asn1.crmf.EncryptedValue;
import org.xipki.asn1.crmf.PKIArchiveOptions;
import org.xipki.asn1.crmf.POPOSigningKeyInput;
import org.xipki.asn1.ocsp.CertID;
import org.xipki.asn1.ocsp.OCSPRequest;
import org.xipki.asn1.ocsp.Request;
import org.xipki.asn1.ocsp.TBSRequest;
import org.xipki.asn1.tcg.CertificateIdentifier;
import org.xipki.asn1.tcg.CommonCriteriaMeasures;
import org.xipki.asn1.tcg.EntityGeoLocation;
import org.xipki.asn1.tcg.EvaluationAssuranceLevel;
import org.xipki.asn1.tcg.EvaluationStatus;
import org.xipki.asn1.tcg.HashedCertificateIdentifier;
import org.xipki.asn1.tcg.StrengthOfFunction;
import org.xipki.asn1.tcg.URIReference;
import org.xipki.asn1.x500.AttributeTypeAndValue;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.CRLEntry;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.DisplayText;
import org.xipki.asn1.x509.DistributionPoint;
import org.xipki.asn1.x509.DistributionPointName;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.asn1.x509.IssuerSerial;
import org.xipki.asn1.x509.NoticeReference;
import org.xipki.asn1.x509.PolicyConstraints;
import org.xipki.asn1.x509.PrivateKeyUsagePeriod;
import org.xipki.asn1.x509.ReasonFlags;
import org.xipki.asn1.x509.RoleSyntax;
import org.xipki.asn1.x509.TBSCertList;
import org.xipki.asn1.x509.UserNotice;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1UtcTime;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.AbstractAsn1Time;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.asn1.crypto.CCMParameters;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.InputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;

/**
 * Builds ASN.1 structures, checks the DER encoding against the expected value derived from the
 * ASN.1 module, and checks that decoding the encoding yields the same structure.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1StructuresTest {

  private interface Parser {
    Asn1Encodable parse(byte[] encoded) throws CodecException;
  }

  private static final byte[] HASH32 = new byte[32];

  static {
    for (int i = 0; i < HASH32.length; i++) {
      HASH32[i] = (byte) i;
    }
  }

  // ---------------- X.509 ----------------

  @Test
  public void testDistributionPoint() throws Exception {
    // RFC 5280 (IMPLICIT TAGS):
    // DistributionPoint ::= SEQUENCE {
    //   distributionPoint [0] DistributionPointName OPTIONAL,  -- CHOICE: EXPLICIT
    //   reasons           [1] ReasonFlags OPTIONAL,
    //   cRLIssuer         [2] GeneralNames OPTIONAL }
    DistributionPoint dp = new DistributionPoint(
        DistributionPointName.ofName(new GeneralNames(GeneralName.ofUri("http://a"))),
        ReasonFlags.keyCompromise,
        new GeneralNames(GeneralName.ofDnsName("c")));

    assertDer("DistributionPoint",
        "3017" + "a00c" + "a00a" + "8608687474703a2f2f61" // [0] { fullName [0] { URI } }
            + "81020640"                                    // [1] reasons: keyCompromise
            + "a203820163",                                 // [2] cRLIssuer { dNSName "c" }
        dp, e -> DistributionPoint.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testPolicyConstraints() throws Exception {
    // both fields are OPTIONAL
    assertDer("requireExplicitPolicy only", "3003800100",
        new PolicyConstraints(BigInteger.ZERO, null), PolicyConstraints::fromEncoded);
    assertDer("inhibitPolicyMapping only", "3003810102",
        new PolicyConstraints(null, BigInteger.TWO), PolicyConstraints::fromEncoded);
    assertDer("both", "3006800100810102",
        new PolicyConstraints(BigInteger.ZERO, BigInteger.TWO), PolicyConstraints::fromEncoded);
  }

  @Test
  public void testPrivateKeyUsagePeriod() throws Exception {
    Instant notAfter = Instant.parse("2030-12-31T23:59:59Z");
    // [1] IMPLICIT GeneralizedTime "20301231235959Z"
    assertDer("notAfter only", "3011810f32303330313233313233353935395a",
        new PrivateKeyUsagePeriod(null, notAfter), PrivateKeyUsagePeriod::fromEncoded);
    assertDer("notBefore only", "3011800f32303330313233313233353935395a",
        new PrivateKeyUsagePeriod(notAfter, null), PrivateKeyUsagePeriod::fromEncoded);
  }

  @Test
  public void testIssuerSerial() throws Exception {
    GeneralNames issuer = new GeneralNames(GeneralName.ofDnsName("a"));
    // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial INTEGER,
    //                             issuerUID UniqueIdentifier OPTIONAL }
    assertDer("without issuerUID", "3008" + "3003820161" + "020101",
        new IssuerSerial(issuer, BigInteger.ONE),
        e -> IssuerSerial.fromAsn1(Asn1Sequence.fromEncoded(e)));

    IssuerSerial is = (IssuerSerial) assertDer("with issuerUID",
        "300c" + "3003820161" + "020101" + "030200ff",
        new IssuerSerial(issuer, new Asn1Integer(BigInteger.ONE),
            new Asn1BitString(new byte[]{(byte) 0xff})),
        e -> IssuerSerial.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertNotNull("issuerUID", is.getIssuerUID());
  }

  @Test
  public void testUserNotice() throws Exception {
    NoticeReference ref = new NoticeReference("Org",
        Arrays.asList(BigInteger.ONE, BigInteger.TWO));
    // NoticeReference ::= SEQUENCE { organization DisplayText,
    //                                noticeNumbers SEQUENCE OF INTEGER }
    assertDer("NoticeReference", "300d" + "0c034f7267" + "3006020101020102", ref,
        e -> NoticeReference.fromAsn1(Asn1Sequence.fromEncoded(e)));

    assertRoundTrip("UserNotice", new UserNotice(ref, "text"),
        e -> UserNotice.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertRoundTrip("UserNotice without noticeRef", new UserNotice(null, "text"),
        e -> UserNotice.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testIssuerAltNameExtension() throws Exception {
    Extension extn = Extension.ofIssuerAlternativeName(false,
        new GeneralNames(GeneralName.ofUri("http://a")));
    Extension decoded = (Extension) assertRoundTrip("issuerAltName", extn,
        e -> Extension.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertEquals("issuerAltName",
        extn.getIssuerAlternativeName(), decoded.getIssuerAlternativeName());
  }

  @Test
  public void testGeneralNames() throws Exception {
    GeneralName[] names = {
        GeneralName.ofRfc822Name("a@example.com"),
        GeneralName.ofDnsName("example.com"),
        GeneralName.ofUri("https://example.com"),
        GeneralName.ofIPAddress("192.168.1.1"),
        GeneralName.ofIPAddress("2001:db8::1"),
        GeneralName.ofRegisteredID(new Asn1Oid("1.2.3.4")),
        GeneralName.ofDirectoryName(caSubject()),
        // [3] ORAddress (IMPLICIT): a dummy SEQUENCE
        GeneralName.ofX400Address(new Asn1Sequence(new Asn1Integer(1)))};

    for (GeneralName name : names) {
      GeneralName decoded = (GeneralName) assertRoundTrip("GeneralName " + name.getTagNo(), name,
          e -> GeneralName.fromAsn1((Asn1TaggedObject) Asn1Sequence.fromEncoded(
              new Asn1Sequence(name).getEncoded()).getObjectAt(0)));
      Assert.assertNotNull("choice data", decoded.getChoiceData());
    }

    Assert.assertEquals("x400Address is IMPLICIT [3]", "a303020101",
        Hex.encode(GeneralName.ofX400Address(new Asn1Sequence(new Asn1Integer(1))).getEncoded()));
  }

  @Test
  public void testTbsCertListWithoutRevokedCertificates() throws Exception {
    // RFC 5280: When there are no revoked certificates, the revoked certificates list MUST
    // be absent.
    AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(new Asn1Oid("1.2.840.10045.4.3.2"));
    Time thisUpdate = new Time(Instant.parse("2026-01-01T00:00:00Z"));

    TBSCertList withEmptyList = new TBSCertList(sigAlg, caSubject(), thisUpdate, null,
        Collections.emptyList(), null);
    TBSCertList withNullList = new TBSCertList(sigAlg, caSubject(), thisUpdate, null,
        null, null);
    Assert.assertEquals("empty list must be omitted",
        Hex.encode(withNullList.getEncoded()), Hex.encode(withEmptyList.getEncoded()));
    // version (optional), signature, issuer, thisUpdate
    Asn1Sequence seq = Asn1Sequence.fromEncoded(withEmptyList.getEncoded());
    Assert.assertTrue("last field must be thisUpdate",
        seq.getObjectAt(seq.size() - 1) instanceof AbstractAsn1Time);
  }

  @Test
  public void testDateOfBirth() throws Exception {
    // 1990-03-05: month and day are padded to two digits
    Attribute attr = Attribute.ofDateOfBirth(1990, 3, 5);
    Assert.assertEquals("19900305000000Z", attr.getDateOfBirth().getText());

    attr = Attribute.ofDateOfBirth(1990, 11, 25);
    Assert.assertEquals("19901125000000Z", attr.getDateOfBirth().getText());

    assertRoundTrip("dateOfBirth", attr, e -> Attribute.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  // ---------------- ESS ----------------

  // ---------------- CMP / CRMF ----------------

  @Test
  public void testErrorMsgContent() throws Exception {
    // ErrorMsgContent ::= SEQUENCE { pKIStatusInfo PKIStatusInfo,
    //   errorCode INTEGER OPTIONAL, errorDetails PKIFreeText OPTIONAL }
    ErrorMsgContent content = new ErrorMsgContent(new PKIStatusInfo(PKIStatus.rejection),
        new Asn1Integer(7), new PKIFreeText("x"));
    assertDer("ErrorMsgContent", "300d" + "3003020102" + "020107" + "30030c0178", content,
        e -> ErrorMsgContent.fromAsn1(Asn1Sequence.fromEncoded(e)));

    assertDer("ErrorMsgContent with status only", "30053003020102",
        new ErrorMsgContent(new PKIStatusInfo(PKIStatus.rejection)),
        e -> ErrorMsgContent.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testChallenge() throws Exception {
    // Challenge ::= SEQUENCE { owf AlgorithmIdentifier OPTIONAL, witness OCTET STRING,
    //   challenge OCTET STRING, encryptedRand [0] EnvelopedData OPTIONAL }
    Challenge challenge = (Challenge) assertDer("Challenge without owf and encryptedRand",
        "3006" + "040101" + "040102",
        new Challenge(null, new byte[]{1}, new byte[]{2}),
        e -> Challenge.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertNull("encryptedRand", challenge.getEncryptedRand());

    assertRoundTrip("Challenge with owf",
        new Challenge(new AlgorithmIdentifier(NistOIDs.id_sha256), new byte[]{1}, new byte[]{2}),
        e -> Challenge.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testPkiArchiveOptions() throws Exception {
    // PKIArchiveOptions ::= CHOICE { encryptedPrivKey [0] EncryptedKey,
    //   keyGenParameters [1] KeyGenParameters, archiveRemGenPrivKey [2] BOOLEAN }
    assertDer("archiveRemGenPrivKey", "8201ff",
        PKIArchiveOptions.ofArchiveRemGenPrivKey(true),
        e -> PKIArchiveOptions.fromAsn1(Asn1TaggedObject.fromEncoded(e)));
    assertDer("keyGenParameters", "810101",
        PKIArchiveOptions.ofKeyGenParameters(new Asn1OctetString(new byte[]{1})),
        e -> PKIArchiveOptions.fromAsn1(Asn1TaggedObject.fromEncoded(e)));
  }

  @Test
  public void testEncryptedValue() throws Exception {
    // EncryptedValue ::= SEQUENCE {
    //   intendedAlg [0] AlgorithmIdentifier OPTIONAL, symmAlg [1] AlgorithmIdentifier OPTIONAL,
    //   encSymmKey  [2] BIT STRING OPTIONAL,          keyAlg  [3] AlgorithmIdentifier OPTIONAL,
    //   valueHint   [4] OCTET STRING OPTIONAL,        encValue BIT STRING }
    EncryptedValue value = new EncryptedValue(null, null,
        new Asn1BitString(new byte[]{(byte) 0xaa}),
        new AlgorithmIdentifier(new Asn1Oid("1.2.3")),
        new Asn1OctetString(new byte[]{1}),
        new Asn1BitString(new byte[]{(byte) 0xbb}));
    assertDer("EncryptedValue",
        "3011" + "820200aa" + "a30406022a03" + "840101" + "030200bb",
        value, e -> EncryptedValue.fromAsn1(Asn1Sequence.fromEncoded(e)));

    assertRoundTrip("EncryptedValue all fields", new EncryptedValue(
            new AlgorithmIdentifier(new Asn1Oid("1.2.1")),
            new AlgorithmIdentifier(new Asn1Oid("1.2.2")),
            new Asn1BitString(new byte[]{1}), new AlgorithmIdentifier(new Asn1Oid("1.2.3")),
            new Asn1OctetString(new byte[]{2}), new Asn1BitString(new byte[]{3})),
        e -> EncryptedValue.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testPopoSigningKeyInput() throws Exception {
    // POPOSigningKeyInput ::= SEQUENCE {
    //   authInfo CHOICE { sender [0] GeneralName, publicKeyMAC PKMACValue },
    //   publicKey SubjectPublicKeyInfo }
    // sender: [0] is EXPLICIT since GeneralName is a CHOICE.
    SubjectPublicKeyInfo spki = Certificate.fromEncoded(Asn1VectorsTest.read("cert-ca-ec.der"))
        .getTBSCertificate().getSubjectPublicKeyInfo();
    POPOSigningKeyInput input = new POPOSigningKeyInput(GeneralName.ofDnsName("a"), spki);
    String spkiHex = Hex.encode(spki.getEncoded());
    String content = "a003820161" + spkiHex;
    assertDer("POPOSigningKeyInput with sender",
        "30" + derLength(content.length() / 2) + content,
        input, e -> POPOSigningKeyInput.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  // ---------------- TSP ----------------

  // ---------------- CMS ----------------

  @Test
  public void testCcmParameters() throws Exception {
    byte[] nonce = new byte[12];
    // CCMParameters ::= SEQUENCE { aes-nonce OCTET STRING (SIZE(7..13)),
    //                              aes-ICVlen AES-CCM-ICVlen DEFAULT 12 }
    assertDer("default icvLen", "300e040c" + Hex.encode(nonce),
        new CCMParameters(nonce, 12), e -> CCMParameters.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertDer("icvLen 16", "3011040c" + Hex.encode(nonce) + "020110",
        new CCMParameters(nonce, 16), e -> CCMParameters.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  // ---------------- OCSP ----------------

  @Test
  public void testTbsRequestVersion() throws Exception {
    OCSPRequest req = OCSPRequest.fromEncoded(Asn1VectorsTest.read("ocsp-req-nononce.der"));
    TBSRequest v1 = req.getTbsRequest();

    // version [0] EXPLICIT Version DEFAULT v1
    TBSRequest v2 = new TBSRequest(Asn1Integer.ONE, null, v1.getRequestList(), null);
    Asn1Sequence seq = Asn1Sequence.fromEncoded(v2.getEncoded());
    Assert.assertEquals("[0] EXPLICIT version", "a003020101",
        Hex.encode(seq.getObjectAt(0).getEncoded()));
    assertRoundTrip("TBSRequest v2", v2, e -> TBSRequest.fromAsn1(Asn1Sequence.fromEncoded(e)));

    // version v1 is omitted
    Assert.assertArrayEquals("TBSRequest v1", v1.getEncoded(),
        new TBSRequest(Asn1Integer.ZERO, null, v1.getRequestList(), null).getEncoded());
  }

  // ---------------- NIST ----------------

  // ---------------- TCG ----------------

  @Test
  public void testTcgStructures() throws Exception {
    AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NistOIDs.id_sha256);
    IssuerSerial issuerSerial = new IssuerSerial(
        new GeneralNames(GeneralName.ofDnsName("a")), BigInteger.ONE);

    // CertificateIdentifier ::= SEQUENCE {
    //   hashedCertIdentifier [0] IMPLICIT HashedCertificateIdentifier OPTIONAL,
    //   genericCertIdentifier [1] IMPLICIT IssuerSerial OPTIONAL }
    assertDer("CertificateIdentifier genericCertIdentifier",
        "300a" + "a108" + "3003820161" + "020101",
        new CertificateIdentifier(null, issuerSerial),
        e -> CertificateIdentifier.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertRoundTrip("CertificateIdentifier both", new CertificateIdentifier(
            new HashedCertificateIdentifier(sha256, HASH32), issuerSerial),
        e -> CertificateIdentifier.fromAsn1(Asn1Sequence.fromEncoded(e)));

    // EntityGeoLocation ::= SEQUENCE { countryCode ISO3166CountryCode,
    //   stateOrProvince [0] IMPLICIT ..., localityName [1] IMPLICIT UTF8String ...,
    //   streetAddress [2] ..., locationCoords [3] ..., postalCode [5] IMPLICIT UTF8String ... }
    assertDer("EntityGeoLocation",
        "3011" + "13024445" + "800544452d4245" + "810142" + "850131",
        new EntityGeoLocation("DE", "DE-BE", "B", null, null, "1"),
        e -> EntityGeoLocation.fromAsn1(Asn1Sequence.fromEncoded(e)));

    // CommonCriteriaMeasures: optional fields are [0]..[4] IMPLICIT
    assertRoundTrip("CommonCriteriaMeasures", new CommonCriteriaMeasures("3.1",
            EvaluationAssuranceLevel.getInstance(4), EvaluationStatus.getInstance(2), true,
            StrengthOfFunction.getInstance(1), new Asn1Oid("1.2.3"),
            new URIReference("http://p", null, null), new Asn1Oid("1.2.4"),
            new URIReference("http://t", sha256, HASH32)),
        e -> CommonCriteriaMeasures.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  // ---------------- helpers ----------------

  private static X500Name caSubject() throws Exception {
    return Certificate.fromEncoded(Asn1VectorsTest.read("cert-ca-ec.der")).getSubject();
  }

  // ---------------- decoding of BouncyCastle encodings (regression tests) ----------------

  @Test
  public void testPkiHeaderWithAllOptionalFields() throws Exception {
    // 3 required fields + 9 OPTIONAL fields [0]..[8]
    PKIHeader header = (PKIHeader) assertDecodes("PKIHeader with all fields",
        "3050020102820161820162a011180f32303230303130313030303030305aa106300406022a03"
            + "a203040101a303040102a403040103a503040104a603040105a70530030c0174"
            + "a80a3008300606022a040500",
        e -> PKIHeader.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertNotNull("recipNonce", header.getRecipNonce());
    Assert.assertNotNull("generalInfo", header.getGeneralInfo());
  }

  @Test
  public void testSignedDataWithTaggedCertificateChoices() throws Exception {
    // certificates: { [2] v2AttrCert, [3] other }
    SignedData sd = (SignedData) assertDecodes("SignedData with v2AttrCert and other",
        "30240201053100300b06092a864886f70d010701a00ea203020101a30706022a030c01783100",
        e -> SignedData.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertTrue("v2AttrCert", sd.getCertificates().hasV2AttributeCertificate());
    Assert.assertTrue("other", sd.getCertificates().hasOtherCertificate());
  }

  @Test
  public void testCertifiedKeyPairWithEncryptedValue() throws Exception {
    // certOrEncCert: [1] encryptedCert EncryptedValue, privateKey: [0] EncryptedValue
    CertifiedKeyPair ckp = (CertifiedKeyPair) assertDecodes(
        "CertifiedKeyPair with EncryptedValue", "3010a106300403020009a006300403020009",
        e -> CertifiedKeyPair.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertNotNull("encryptedCert",
        ckp.getCertOrEncCert().getEncryptedCert().getEncryptedValue());
    Assert.assertNotNull("privateKey", ckp.getPrivateKey().getEncryptedValue());
  }

  @Test
  public void testEncKeyWithIdWithoutIdentifier() throws Exception {
    // EncKeyWithID ::= SEQUENCE { privateKey PrivateKeyInfo, identifier CHOICE {..} OPTIONAL }
    EncKeyWithID obj = new EncKeyWithID(new PrivateKeyInfo(
        new AlgorithmIdentifier(AlgorithmOIDs.id_Ed25519), new Asn1OctetString(new byte[32])));
    assertDer("EncKeyWithID without identifier",
        "3030302e020100300506032b657004220420" + Hex.encode(new byte[32]),
        obj, e -> EncKeyWithID.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testDisplayTextVisibleString() throws Exception {
    // RFC 6818: VisibleString is allowed in DisplayText
    UserNotice notice = (UserNotice) assertDecodes("UserNotice with VisibleString",
        "3012300a1a034f726730030201011a0474657874",
        e -> UserNotice.fromAsn1(Asn1Sequence.fromEncoded(e)));
    Assert.assertEquals("organization", "Org", notice.getNoticeRef().getOrganization().string());
    Assert.assertEquals("explicitText", "text", notice.explicitText());

    assertDer("UserNotice with VisibleString explicitText", "30061a0474657874",
        new UserNotice(null, new DisplayText(DisplayText.ContentType.VisibleString, "text")),
        e -> UserNotice.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testRoleSyntax() throws Exception {
    // RoleSyntax ::= SEQUENCE { roleAuthority [0] GeneralNames OPTIONAL,
    //                           roleName      [1] GeneralName }
    assertDecodes("RoleSyntax", "300ea003820161a107860575726e3a72",
        e -> RoleSyntax.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertRejected("RoleSyntax without roleName", "3005a003820161",
        e -> RoleSyntax.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testOcspRequestExtensionsTag() throws Exception {
    // Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT Extensions
    //                        OPTIONAL }
    assertDecodes("Request",
        "30273018300b06096086480165030402010402000004020000020101a00b3009300706022a03040100",
        e -> Request.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertRejected("Request with tag [1]",
        "30273018300b06096086480165030402010402000004020000020101a10b3009300706022a03040100",
        e -> Request.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testPopoSigningKeyInputSenderTag() throws Exception {
    // authInfo CHOICE { sender [0] GeneralName, publicKeyMAC PKMACValue }
    String spki = "302a300506032b6570032100" + Hex.encode(new byte[32]);
    assertDecodes("POPOSigningKeyInput", "3031a003820161" + spki,
        e -> POPOSigningKeyInput.fromAsn1(Asn1Sequence.fromEncoded(e)));
    assertRejected("POPOSigningKeyInput with sender tag [1]", "3031a103820161" + spki,
        e -> POPOSigningKeyInput.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testCertificateWithTrailingElement() throws Exception {
    byte[] encoded;
    try (InputStream is = Asn1StructuresTest.class.getResourceAsStream(
        "/asn1-vectors/cert-ca-ec.der")) {
      encoded = is.readAllBytes();
    }

    Asn1Sequence seq = Asn1Sequence.fromEncoded(encoded);
    assertDecodes("Certificate", Hex.encode(encoded), Certificate::fromEncoded);

    Asn1Encodable[] elements = new Asn1Encodable[seq.size() + 1];
    for (int i = 0; i < seq.size(); i++) {
      elements[i] = seq.getObjectAt(i);
    }
    elements[seq.size()] = Asn1Null.INSTANCE;
    assertRejected("Certificate with trailing element",
        Hex.encode(new Asn1Sequence(elements).getEncoded()), Certificate::fromEncoded);
  }

  @Test
  public void testNegativeSerialNumber() throws Exception {
    byte[] encoded;
    try (InputStream is = Asn1StructuresTest.class.getResourceAsStream(
        "/asn1-vectors/cert-ca-ec.der")) {
      encoded = is.readAllBytes();
    }

    // Certificate ::= SEQUENCE { tbsCertificate, ... }, serialNumber follows the version [0].
    Asn1Sequence cert = Asn1Sequence.fromEncoded(encoded);
    Asn1Sequence tbs = cert.getSequenceAt(0);
    Asn1Encodable[] tbsElements = new Asn1Encodable[tbs.size()];
    for (int i = 0; i < tbs.size(); i++) {
      tbsElements[i] = tbs.getObjectAt(i);
    }
    tbsElements[1] = new Asn1Integer(-5);
    String negativeSerialCert = Hex.encode(new Asn1Sequence(new Asn1Sequence(tbsElements),
        cert.getObjectAt(1), cert.getObjectAt(2)).getEncoded());
    assertRejected("Certificate with negative serial number", negativeSerialCert,
        Certificate::fromEncoded);

    // CRLEntry ::= SEQUENCE { userCertificate CertificateSerialNumber, revocationDate Time, ...}
    String revocationDate = Hex.encode(new Asn1UtcTime(Instant.parse("2026-01-01T00:00:00Z"))
        .getEncoded());
    Parser crlEntryParser = e -> CRLEntry.fromAsn1(Asn1Sequence.fromEncoded(e));
    assertDecodes("CRLEntry", "3012020105" + revocationDate, crlEntryParser);
    assertRejected("CRLEntry with negative serial number", "30120201fb" + revocationDate,
        crlEntryParser);

    // OCSP CertID
    Asn1Sequence certId = new Asn1Sequence(AlgorithmIdentifier.build(AlgorithmOIDs.id_sha1),
        new Asn1OctetString(new byte[20]), new Asn1OctetString(new byte[20]),
        new Asn1Integer(-5));
    assertRejected("CertID with negative serial number", Hex.encode(certId.getEncoded()),
        e -> CertID.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testNegativeIntegers() throws Exception {
    // BasicConstraints: pathLenConstraint INTEGER (0..MAX)
    assertDecodes("BasicConstraints", "30060101ff020100", BasicConstraints::fromEncoded);
    assertRejected("BasicConstraints with negative pathLenConstraint", "30060101ff0201ff",
        BasicConstraints::fromEncoded);

    // DSS-Sig-Value: r and s are in [1, q-1]
    assertRejected("DSS-Sig-Value with negative r", "30060201ff020101",
        DssSigValue::fromEncoded);

    // RSAPublicKey: negative modulus
    assertRejected("RSAPublicKey with negative modulus", "30060201ff020103",
        RSAPublicKey::fromEncoded);

    // CRL number extension: CRLNumber ::= INTEGER (0..MAX)
    try {
      Asn1Integer.fromEncodedNonNegative(Hex.decode("0201ff"));
      Assert.fail("negative CRLNumber accepted");
    } catch (CodecException e) {
      // expected
    }

    // certReqId -1 is allowed (RFC 9480, e.g. for p10cr)
    assertDecodes("CertResponse with certReqId -1", "30080201ff3003020100",
        e -> CertResponse.fromAsn1(Asn1Sequence.fromEncoded(e)));
  }

  @Test
  public void testPbmParameterIterationCount() throws Exception {
    AlgorithmIdentifier owf = AlgorithmIdentifier.build(AlgorithmOIDs.id_sha256);
    AlgorithmIdentifier mac = AlgorithmIdentifier.build(AlgorithmOIDs.id_hmacWithSHA256);
    Parser parser = e -> PBMParameter.fromAsn1(Asn1Sequence.fromEncoded(e));

    assertRoundTrip("PBMParameter", new PBMParameter(new byte[16], owf, 10000, mac), parser);

    for (BigInteger iterationCount : new BigInteger[] {
        BigInteger.ZERO, BigInteger.ONE.negate(), BigInteger.ONE.shiftLeft(31)}) {
      Asn1Sequence seq = new Asn1Sequence(new Asn1OctetString(new byte[16]), owf,
          new Asn1Integer(iterationCount), mac);
      assertRejected("PBMParameter with iterationCount " + iterationCount,
          Hex.encode(seq.getEncoded()), parser);
    }
  }

  // ---------------- toString ----------------

  @Test
  public void testToString() throws Exception {
    ErrorMsgContent error = new ErrorMsgContent(new PKIStatusInfo(PKIStatus.rejection),
        new Asn1Integer(7), new PKIFreeText("x"));
    ToStringAssert.assertFields("ErrorMsgContent", error,
        "pkiStatusInfo", "status", "errorCode", "errorDetails");
    Assert.assertTrue("PKIStatus name", error.toString().contains("status: rejection"));

    ToStringAssert.assertFields("PKIBody", PKIBody.ofError(error), "error", "pkiStatusInfo");
    Assert.assertEquals("pkiconf", "PKIBody:\n  pkiconf: NULL", PKIBody.ofPkiconf().toString());

    ToStringAssert.assertFields("UserNotice", new UserNotice(new NoticeReference("Org",
        Arrays.asList(BigInteger.ONE, BigInteger.TWO)), "text"),
        "noticeRef", "organization", "noticeNumbers", "explicitText");

    ToStringAssert.assertFields("CCMParameters", new CCMParameters(new byte[12], 16),
        "nonce", "icvLen");

    Assert.assertEquals("PKIStatus", "PKIStatus:\n  accepted", PKIStatus.accepted.toString());
    Assert.assertEquals("AttributeTypeAndValue",
        "AttributeTypeAndValue:\n  type: commonName\n  value: abc",
        new AttributeTypeAndValue(X509OIDs.commonName, new Asn1Utf8String("abc")).toString());
  }

  /**
   * Decodes the encoding (e.g. generated by BouncyCastle) and checks that the re-encoding is
   * identical.
   */
  private static Asn1Encodable assertDecodes(String name, String hex, Parser parser)
      throws Exception {
    byte[] encoded = Hex.decode(hex);
    Asn1Encodable decoded;
    try {
      decoded = parser.parse(encoded);
    } catch (Exception e) {
      throw new AssertionError(name + ": could not parse: " + e, e);
    }
    Assert.assertEquals(name + ": re-encoded", hex, Hex.encode(decoded.getEncoded()));
    ToStringAssert.assertPrintable(name, decoded);
    return decoded;
  }

  /**
   * Asserts that decoding the invalid encoding fails with a {@link CodecException}.
   */
  private static void assertRejected(String name, String hex, Parser parser) {
    try {
      parser.parse(Hex.decode(hex));
      Assert.fail(name + ": invalid encoding accepted");
    } catch (CodecException e) {
      // expected
    }
  }

  private static Asn1Encodable assertDer(String name, String expectedHex, Asn1Encodable obj,
                                         Parser parser) throws Exception {
    Assert.assertEquals(name + ": DER", expectedHex, Hex.encode(obj.getEncoded()));
    return assertRoundTrip(name, obj, parser);
  }

  private static Asn1Encodable assertRoundTrip(String name, Asn1Encodable obj, Parser parser)
      throws Exception {
    byte[] encoded = obj.getEncoded();
    Asn1Encodable decoded;
    try {
      decoded = parser.parse(encoded);
    } catch (Exception e) {
      throw new AssertionError(name + ": could not parse " + Hex.encode(encoded) + ": " + e, e);
    }
    Assert.assertEquals(name + ": decoded re-encoded", Hex.encode(encoded),
        Hex.encode(decoded.getEncoded()));
    ToStringAssert.assertPrintable(name, decoded);
    Assert.assertEquals(name + ": toString", obj.toString(), decoded.toString());
    return decoded;
  }

  private static String derLength(int len) {
    if (len < 0x80) {
      return String.format("%02x", len);
    } else if (len < 0x100) {
      return "81" + String.format("%02x", len);
    } else {
      return "82" + String.format("%04x", len);
    }
  }

}
