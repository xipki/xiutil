// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.ccc.EndpointCertificateExtensionSchema;
import org.xipki.asn1.ccc.InstanceCACertificateExtensionSchema;
import org.xipki.asn1.ccc.SBxDKisCertificateExtensionSchema;
import org.xipki.asn1.ccc.SimpleExtensionSchema;
import org.xipki.asn1.cert.CtLog;
import org.xipki.asn1.cert.MicrosoftCertificateTemplate;
import org.xipki.asn1.cert.TLSFeatures;
import org.xipki.asn1.ocsp.CertHash;
import org.xipki.asn1.ocsp.PreferredSignatureAlgorithms;
import org.xipki.asn1.rpki.ASIdentifiers;
import org.xipki.asn1.rpki.IPAddrBlocks;
import org.xipki.asn1.smime.SMIMECapabilities;
import org.xipki.asn1.spdm.SpdmCertOids;
import org.xipki.asn1.stir.TNAuthorizationList;
import org.xipki.asn1.tcg.TcgUeid;
import org.xipki.asn1.x509.qualified.BiometricSyntax;
import org.xipki.asn1.x509.qualified.QCStatements;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;

/**
 * <pre>
 * Extension         ::=   SEQUENCE {
 *     extnId            EXTENSION.&amp;id ({ExtensionSet}),
 *     critical          BOOLEAN DEFAULT FALSE,
 *     extnValue         OCTET STRING }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Extension extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<Extension> {

    public Seq1(Extension... entries) {
      super(entries);
    }

    public Seq1(List<Extension> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected Extension newType(AbstractAsn1Collection seq, int index) throws CodecException {
      return Extension.fromAsn1(seq.getSequenceAt(index));
    }
  }

  private final Asn1Oid extnId;
  private final boolean critical;
  private final Asn1OctetString value;

  private boolean parsed;

  // subjectDirectoryAttributes = new Asn1Oid("2.5.29.9");
  private SubjectDirectoryAttributes subjectDirectoryAttributes;

  // subjectKeyIdentifier = new Asn1Oid("2.5.29.14");
  private SubjectKeyIdentifier subjectKeyIdentifier;

  // keyUsage = new Asn1Oid("2.5.29.15");
  private KeyUsage keyUsage;

  // privateKeyUsagePeriod = new Asn1Oid("2.5.29.16");
  private PrivateKeyUsagePeriod privateKeyUsagePeriod;

  // subjectAlternativeName = new Asn1Oid("2.5.29.17");
  private GeneralNames subjectAlternativeName;

  // issuerAlternativeName = new Asn1Oid("2.5.29.18");
  private GeneralNames issuerAlternativeName;

  // basicConstraints = new Asn1Oid("2.5.29.19");
  private BasicConstraints basicConstraints;

  // cRLNumber = new Asn1Oid("2.5.29.20");
  private Asn1Integer cRLNumber;

  // reasonCode = new Asn1Oid("2.5.29.21");
  private CRLReason reasonCode;

  // instructionCode = new Asn1Oid("2.5.29.23");
  private Asn1Oid instructionCode;

  // invalidityDate = new Asn1Oid("2.5.29.24");
  private Asn1GeneralizedTime invalidityDate;

  // deltaCRLIndicator = new Asn1Oid("2.5.29.27");
  private Asn1Integer deltaCRLIndicator;

  // issuingDistributionPoint = new Asn1Oid("2.5.29.28");
  private IssuingDistributionPoint issuingDistributionPoint;

  // certificateIssuer = new Asn1Oid("2.5.29.29");
  private GeneralNames certificateIssuer;

  // nameConstraints = new Asn1Oid("2.5.29.30");
  private NameConstraints nameConstraints;

  // cRLDistributionPoints = new Asn1Oid("2.5.29.31");
  private CRLDistributionPoints cRLDistributionPoints;

  // certificatePolicies = new Asn1Oid("2.5.29.32");
  private CertificatePolicies certificatePolicies;

  // policyMappings = new Asn1Oid("2.5.29.33");
  private PolicyMappings policyMappings;

  // authorityKeyIdentifier = new Asn1Oid("2.5.29.35");
  private AuthorityKeyIdentifier authorityKeyIdentifier;

  // policyConstraints = new Asn1Oid("2.5.29.36");
  private PolicyConstraints policyConstraints;

  // extendedKeyUsage = new Asn1Oid("2.5.29.37");
  private ExtendedKeyUsage extendedKeyUsage;

  // freshestCRL = new Asn1Oid("2.5.29.46");
  private CRLDistributionPoints freshestCRL;

  // inhibitAnyPolicy = new Asn1Oid("2.5.29.54");
  private Asn1Integer inhibitAnyPolicy; // skipTests

  // authorityInfoAccess = new Asn1Oid("1.3.6.1.5.5.7.1.1");
  private AuthorityInfoAccessSyntax authorityInfoAccess;

  // subjectInfoAccess = new Asn1Oid("1.3.6.1.5.5.7.1.11");
  private SubjectInfoAccessSyntax subjectInfoAccess;

  private SMIMECapabilities smimeCapabilities;

  // biometricInfo = new Asn1Oid("1.3.6.1.5.5.7.1.2");
  private BiometricSyntax biometricInfo;

  // qCStatements = new Asn1Oid("1.3.6.1.5.5.7.1.3");
  private QCStatements qCStatements;

  // noRevAvail = new Asn1Oid("2.5.29.56");
  private Asn1Null noRevAvail;

  // expiredCertsOnCRL = new Asn1Oid("2.5.29.60");
  private Asn1GeneralizedTime expiredCertsOnCRL;

  private Asn1Null ocspNoCheck;

  private Asn1OctetString ocspNonce;

  private PreferredSignatureAlgorithms preferredSignatureAlgorithms;

  // ----- Certificate Transparency -----
  private Asn1Null preCertificate;

  // Certificate Transparency (RFC 6962)
  // id_SignedCertificateTimestampList = new Asn1Oid("1.3.6.1.4.1.11129.2.4.2");
  private Asn1OctetString signedCertificateTimestampList;

  // ASIdentifiers = new Asn1Oid("1.3.6.1.5.5.7.1.8");
  private ASIdentifiers aSIdentifiers;

  // ASIdentifiersV2 = new Asn1Oid("1.3.6.1.5.5.7.1.29");
  private ASIdentifiers aSIdentifiersV2;

  // IPAddrBlocks = new Asn1Oid("1.3.6.1.5.5.7.1.7");
  private IPAddrBlocks iPAddrBlocks;

  // IPAddrBlocksV2 = new Asn1Oid("1.3.6.1.5.5.7.1.28");
  private IPAddrBlocks iPAddrBlocksV2;

  // id_pe_tlsfeature = new Asn1Oid("1.3.6.1.5.5.7.1.24");
  private TLSFeatures tlsFeatures;

  // id_DMTF_SPDM_extension = new Asn1Oid("1.3.6.1.4.1.412.274.6")
  private SpdmCertOids spdmExtension;

  //---- CCC
  private SimpleExtensionSchema CCC_F_External_CACert;

  private SimpleExtensionSchema CCC_J_VehicleOEMCACert;

  private SimpleExtensionSchema CCC_K_VehicleCert;

  private SimpleExtensionSchema CCC_M_VehicleOEMCACert;

  private SimpleExtensionSchema CCC_P_VehicleOEMEncCert;

  private SimpleExtensionSchema CCC_Q_VehicleOEMSigCert;

  private SimpleExtensionSchema CCC_R_CertificationBodyCert;

  private SimpleExtensionSchema CCC_S_SBxDKisIntermediateCACert;

  private SimpleExtensionSchema CCC_U_SBxDKisRootCACert;

  private SimpleExtensionSchema CCC_DeviceEncCert;

  private SimpleExtensionSchema CCC_VehicleIntermediateCert;

  private InstanceCACertificateExtensionSchema CCC_E_Instance_CACert;

  private EndpointCertificateExtensionSchema CCC_H_EndpointCert;

  private SBxDKisCertificateExtensionSchema CCC_T_SBxDKisEndpointCert;

  // ----- chinese GM/T 0015 -----
  private Asn1PrintableString CN_ResidentIdCardNumber;

  private Asn1Utf8String CN_PassportNumber;

  private Asn1PrintableString CN_SocialInsuranceNumber;

  private Asn1PrintableString CN_UnifiedSocialCreditCode;

  // ----- STIR -----
  private TNAuthorizationList tNAuthList;

  // ----- Microsoft -----
  private GeneralNames microsoftSecurityIdentifier;

  private MicrosoftCertificateTemplate microsoftCertificateTemplate;

  // ----- Caliptra -----
  private TcgUeid tcgDiceUeid;

  // ----- ISIS-MTT -----
  private CertHash certHash;

  // BRSKI
  private Asn1IA5String masaUrl;

  private Extension(Asn1Oid extnId, boolean critical, byte[] value) {
    this.extnId = Args.notNull(extnId, "extnId");
    this.critical = critical;
    this.value = new Asn1OctetString(Args.notNull(value, "value"));
  }

  public static Extension createNoParse(Asn1Oid extnId, boolean critical, Asn1Encodable value) {
    return new Extension(extnId, critical, value.getEncoded(Asn1Encoding.DER));
  }

  public static Extension create(Asn1Oid extnId, boolean critical, Asn1Encodable value)
      throws CodecException {
    Extension r = createNoParse(extnId, critical, value.toAsn1Primitive());
    r.parseValue();
    return r;
  }

  private static Extension create2(Asn1Oid extnId, boolean critical, Asn1Encodable value) {
    Extension r = createNoParse(extnId, critical, value.toAsn1Primitive());
    r.parsed = true;
    return r;
  }

  public static Extension fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = seq.size();
    Args.range(size, "sequence size", 2, 3);

    Asn1Oid extnId = seq.getOidAt(0);
    boolean critical = size != 2 && seq.getBooleanAt(1).isTrue();
    Asn1OctetString value = seq.getOctetStringAt(size - 1);
    Extension r = new Extension(extnId, critical, value.getOctets());
    r.parseValue();
    return r;
  }

  public static Extension ofSubjectDirectoryAttributes(
      boolean critical, SubjectDirectoryAttributes value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.subjectDirectoryAttributes, critical, value);
    extn.subjectDirectoryAttributes = value;
    return extn;
  }

  public static Extension ofSubjectKeyIdentifier(boolean critical, SubjectKeyIdentifier value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.subjectKeyIdentifier, critical, value);
    extn.subjectKeyIdentifier = value;
    return extn;
  }

  public static Extension ofSubjectKeyIdentifier(boolean critical, byte[] value) {
    Args.notNull(value, "value");
    SubjectKeyIdentifier asn1 = new SubjectKeyIdentifier(value);
    Extension extn = create2(ExtensionOIDs.subjectKeyIdentifier, critical, asn1);
    extn.subjectKeyIdentifier = asn1;
    return extn;
  }

  public static Extension ofKeyUsage(boolean critical, KeyUsage value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.keyUsage, critical, value);
    extn.keyUsage = value;
    return extn;
  }

  public static Extension ofPrivateKeyUsagePeriod(boolean critical, PrivateKeyUsagePeriod value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.privateKeyUsagePeriod, critical, value);
    extn.privateKeyUsagePeriod = value;
    return extn;
  }

  public static Extension ofSubjectAlternativeName(boolean critical, GeneralNames value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.subjectAlternativeName, critical, value);
    extn.subjectAlternativeName = value;
    return extn;
  }

  public static Extension ofIssuerAlternativeName(boolean critical, GeneralNames value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.issuerAlternativeName, critical, value);
    extn.issuerAlternativeName = value;
    return extn;
  }

  public static Extension ofBasicConstraints(boolean critical, BasicConstraints value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.basicConstraints, critical, value);
    extn.basicConstraints = value;
    return extn;
  }

  public static Extension ofCRLNumber(boolean critical, Asn1Integer value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.cRLNumber, critical, value);
    extn.cRLNumber = value;
    return extn;
  }

  public static Extension ofCRLNumber(boolean critical, BigInteger value) {
    Args.notNull(value, "value");
    return ofCRLNumber(critical, new Asn1Integer(value));
  }

  public static Extension ofCRLNumber(boolean critical, long value) {
    return ofCRLNumber(critical, new Asn1Integer(value));
  }

  public static Extension ofReasonCode(boolean critical, CRLReason value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.reasonCode, critical, value);
    extn.reasonCode = value;
    return extn;
  }

  public static Extension ofInstructionCode(boolean critical, Asn1Oid value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.reasonCode, critical, value);
    extn.instructionCode = value;
    return extn;
  }

  public static Extension ofInvalidityDate(boolean critical, Instant value) {
    Args.notNull(value, "value");
    Asn1GeneralizedTime asn1Value = new Asn1GeneralizedTime(value);
    Extension extn = create2(ExtensionOIDs.invalidityDate, critical, asn1Value);
    extn.invalidityDate = asn1Value;
    return extn;
  }

  public static Extension ofDeltaCRLIndicator(boolean critical, Asn1Integer value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.deltaCRLIndicator, critical, value);
    extn.deltaCRLIndicator = value;
    return extn;
  }

  public static Extension ofDeltaCRLIndicator(boolean critical, long value) {
    Asn1Integer asn1Value = new Asn1Integer(value);
    Extension extn = create2(ExtensionOIDs.deltaCRLIndicator, critical, asn1Value);
    extn.deltaCRLIndicator = asn1Value;
    return extn;
  }

  public static Extension ofIssuingDistributionPoint(
      boolean critical, IssuingDistributionPoint value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.issuingDistributionPoint, critical, value);
    extn.issuingDistributionPoint = value;
    return extn;
  }

  public static Extension ofCertificateIssuer(boolean critical, GeneralNames value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.certificateIssuer, critical, value);
    extn.certificateIssuer = value;
    return extn;
  }

  public static Extension ofNameConstraints(boolean critical, NameConstraints value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.nameConstraints, critical, value);
    extn.nameConstraints = value;
    return extn;
  }

  public static Extension ofCRLDistributionPoints(boolean critical, CRLDistributionPoints value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.cRLDistributionPoints, critical, value);
    extn.cRLDistributionPoints = value;
    return extn;
  }

  public static Extension ofCertificatePolicies(boolean critical, CertificatePolicies value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.certificatePolicies, critical, value);
    extn.certificatePolicies = value;
    return extn;
  }

  public static Extension ofPolicyMappings(boolean critical, PolicyMappings value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.policyMappings, critical, value);
    extn.policyMappings = value;
    return extn;
  }

  public static Extension ofAuthorityKeyIdentifier(boolean critical, AuthorityKeyIdentifier value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.authorityKeyIdentifier, critical, value);
    extn.authorityKeyIdentifier = value;
    return extn;
  }

  public static Extension ofPolicyConstraints(boolean critical, PolicyConstraints value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.policyConstraints, critical, value);
    extn.policyConstraints = value;
    return extn;
  }

  public static Extension ofExtendedKeyUsage(boolean critical, ExtendedKeyUsage value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.extendedKeyUsage, critical, value);
    extn.extendedKeyUsage = value;
    return extn;
  }

  public static Extension ofFreshestCRL(boolean critical, CRLDistributionPoints value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.freshestCRL, critical, value);
    extn.freshestCRL = value;
    return extn;
  }

  public static Extension ofInhibitAnyPolicy(boolean critical, Asn1Integer value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.inhibitAnyPolicy, critical, value);
    extn.inhibitAnyPolicy = value;
    return extn;
  }

  public static Extension ofAuthorityInfoAccess(boolean critical, AuthorityInfoAccessSyntax value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.authorityInfoAccess, critical, value);
    extn.authorityInfoAccess = value;
    return extn;
  }

  public static Extension ofSubjectInfoAccess(boolean critical, SubjectInfoAccessSyntax value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.subjectInfoAccess, critical, value);
    extn.subjectInfoAccess = value;
    return extn;
  }

  public static Extension ofSmimeCapabilities(boolean critical, SMIMECapabilities value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_smimeCapabilities, critical, value);
    extn.smimeCapabilities = value;
    return extn;
  }

  public static Extension ofBiometricInfo(boolean critical, BiometricSyntax value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.biometricInfo, critical, value);
    extn.biometricInfo = value;
    return extn;
  }

  public static Extension ofQCStatements(boolean critical, QCStatements value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.qCStatements, critical, value);
    extn.qCStatements = value;
    return extn;
  }

  public static Extension ofNoRevAvail(boolean critical) {
    Extension extn = create2(ExtensionOIDs.noRevAvail, critical, Asn1Null.INSTANCE);
    extn.noRevAvail = Asn1Null.INSTANCE;
    return extn;
  }

  public static Extension ofExpiredCertsOnCRL(boolean critical, Instant value) {
    Args.notNull(value, "value");
    Asn1GeneralizedTime asn1Value = new Asn1GeneralizedTime(value);
    Extension extn = create2(ExtensionOIDs.expiredCertsOnCRL, critical, asn1Value);
    extn.expiredCertsOnCRL = asn1Value;
    return extn;
  }

  public static Extension ofOcspNoCheck(boolean critical) {
    Extension extn = create2(ExtensionOIDs.id_pkix_ocsp_nocheck, critical, Asn1Null.INSTANCE);
    extn.ocspNoCheck = Asn1Null.INSTANCE;
    return extn;
  }

  public static Extension ofOcspNonce(boolean critical, Asn1OctetString value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_pkix_ocsp_nonce, critical, value);
    extn.ocspNonce = value;
    return extn;
  }

  public static Extension ofOcspNonce(boolean critical, byte[] value) {
    Args.notEmptyBytes(value, "value");
    Asn1OctetString asn1Value = new Asn1OctetString(value);
    Extension extn = create2(ExtensionOIDs.id_pkix_ocsp_nonce, critical, asn1Value);
    extn.ocspNonce = asn1Value;
    return extn;
  }

  public static Extension ofPreferredSignatureAlgorithms(
      boolean critical, PreferredSignatureAlgorithms value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_pkix_ocsp_prefSigAlgs, critical, value);
    extn.preferredSignatureAlgorithms = value;
    return extn;
  }

  public static Extension ofPreCertificate(boolean critical) {
    Extension extn = create2(ExtensionOIDs.id_precertificate, critical, Asn1Null.INSTANCE);
    extn.preCertificate = Asn1Null.INSTANCE;
    return extn;
  }

  public static Extension ofSignedCertificateTimestampList(boolean critical, byte[] value) {
    Args.notNull(value, "value");
    Asn1OctetString asn1Value = new Asn1OctetString(value);
    Extension extn = create2(ExtensionOIDs.id_SignedCertificateTimestampList, critical, asn1Value);
    extn.signedCertificateTimestampList = asn1Value;
    return extn;
  }

  public static Extension ofASIdentifiers(boolean critical, ASIdentifiers value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.ASIdentifiers, critical, value);
    extn.aSIdentifiers = value;
    return extn;
  }

  public static Extension ofASIdentifiersV2(boolean critical, ASIdentifiers value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.ASIdentifiersV2, critical, value);
    extn.aSIdentifiersV2 = value;
    return extn;
  }

  public static Extension ofIPAddrBlocks(boolean critical, IPAddrBlocks value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.IPAddrBlocks, critical, value);
    extn.iPAddrBlocks = value;
    return extn;
  }

  public static Extension ofIPAddrBlocksV2(boolean critical, IPAddrBlocks value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.IPAddrBlocksV2, critical, value);
    extn.iPAddrBlocksV2 = value;
    return extn;
  }

  public static Extension ofTlsFeatures(boolean critical, TLSFeatures value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_pe_tlsfeature, critical, value);
    extn.tlsFeatures = value;
    return extn;
  }

  public static Extension ofSpdmExtension(boolean critical, SpdmCertOids value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_dmtf_spdm_extension, critical, value);
    extn.spdmExtension = value;
    return extn;
  }

  public static Extension ofCCC_F_External_CACert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_F_External_CA_Cert, critical, value);
    extn.CCC_F_External_CACert = value;
    return extn;
  }

  public static Extension ofCCC_J_VehicleOEMCACert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_J_VehicleOEM_CA_Cert, critical, value);
    extn.CCC_J_VehicleOEMCACert = value;
    return extn;
  }

  public static Extension ofCCC_K_VehicleCert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_K_Vehicle_Cert, critical, value);
    extn.CCC_K_VehicleCert = value;
    return extn;
  }

  public static Extension ofCCC_M_VehicleOEMCACert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_M_VehicleOEM_CA_Cert, critical, value);
    extn.CCC_M_VehicleOEMCACert = value;
    return extn;
  }

  public static Extension ofCCC_P_VehicleOEMEncCert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_P_VehicleOEM_Enc_Cert, critical, value);
    extn.CCC_P_VehicleOEMEncCert = value;
    return extn;
  }

  public static Extension ofCCC_Q_VehicleOEMSigCert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_Q_VehicleOEM_Sig_Cert, critical, value);
    extn.CCC_Q_VehicleOEMSigCert = value;
    return extn;
  }

  public static Extension ofCCC_R_CertificationBodyCert(
      boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_R_CertificationBody_Cert, critical, value);
    extn.CCC_R_CertificationBodyCert = value;
    return extn;
  }

  public static Extension ofCCC_S_SBxDKisIntermediateCACert(
      boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_S_SBxDKis_Intermediate_CA_Cert, critical, value);
    extn.CCC_S_SBxDKisIntermediateCACert = value;
    return extn;
  }

  public static Extension ofCCC_U_SBxDKisRootCACert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_U_SBxDKis_RootCA_Cert, critical, value);
    extn.CCC_U_SBxDKisRootCACert = value;
    return extn;
  }

  public static Extension ofCCC_DeviceEncCert(boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_Device_Enc_Cert, critical, value);
    extn.CCC_DeviceEncCert = value;
    return extn;
  }

  public static Extension ofCCC_VehicleIntermediateCert(
      boolean critical, SimpleExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_Vehicle_Intermediate_Cert, critical, value);
    extn.CCC_VehicleIntermediateCert = value;
    return extn;
  }

  public static Extension ofCCC_E_Instance_CACert(
      boolean critical, InstanceCACertificateExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_E_Instance_CA_Cert, critical, value);
    extn.CCC_E_Instance_CACert = value;
    return extn;
  }

  public static Extension ofCCC_H_EndpointCert(
      boolean critical, EndpointCertificateExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_H_Endpoint_Cert, critical, value);
    extn.CCC_H_EndpointCert = value;
    return extn;
  }

  public static Extension ofCCC_T_SBxDKisEndpointCert(
      boolean critical, SBxDKisCertificateExtensionSchema value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_ccc_T_SBxDKis_Endpoint_Cert, critical, value);
    extn.CCC_T_SBxDKisEndpointCert = value;
    return extn;
  }

  public static Extension ofCN_ResidentIdCardNumber(boolean critical, String value) {
    Args.notNull(value, "value");
    Asn1PrintableString asn1Value = new Asn1PrintableString(value);
    Extension extn = create2(ExtensionOIDs.id_cn_residentIdCardNumber, critical, asn1Value);
    extn.CN_ResidentIdCardNumber = asn1Value;
    return extn;
  }

  public static Extension ofCN_PassportNumber(boolean critical, String value) {
    Args.notNull(value, "value");
    Asn1Utf8String asn1Value = new Asn1Utf8String(value);
    Extension extn = create2(ExtensionOIDs.id_cn_passportNumber, critical, asn1Value);
    extn.CN_PassportNumber = asn1Value;
    return extn;
  }

  public static Extension ofCN_SocialInsuranceNumber(boolean critical, String value) {
    Args.notNull(value, "value");
    Asn1PrintableString asn1Value = new Asn1PrintableString(value);
    Extension extn = create2(ExtensionOIDs.id_cn_socialInsuranceNumber, critical, asn1Value);
    extn.CN_SocialInsuranceNumber = asn1Value;
    return extn;
  }

  public static Extension ofCN_UnifiedSocialCreditCode(boolean critical, String value) {
    Args.notNull(value, "value");
    Asn1PrintableString asn1Value = new Asn1PrintableString(value);
    Extension extn = create2(ExtensionOIDs.id_cn_unifiedSocialCreditCode, critical, asn1Value);
    extn.CN_UnifiedSocialCreditCode = asn1Value;
    return extn;
  }

  public static Extension ofTNAuthList(boolean critical, TNAuthorizationList value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_pe_TNAuthList, critical, value);
    extn.tNAuthList = value;
    return extn;
  }

  public static Extension ofMicrosoftSecurityIdentifier(boolean critical, GeneralNames value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_microsoft_SecurityIdentifier, critical, value);
    extn.microsoftSecurityIdentifier = value;
    return extn;
  }

  public static Extension ofMicrosoftSecurityIdentifier(
      boolean critical, MicrosoftCertificateTemplate value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_microsoft_CertificateTemplateInformation,
        critical, value);
    extn.microsoftCertificateTemplate = value;
    return extn;
  }

  public static Extension ofTcgDiceUeid(boolean critical, byte[] ueid) {
    Args.notEmptyBytes(ueid, "ueid");
    return ofTcgDiceUeid(critical, new TcgUeid(ueid));
  }

  public static Extension ofTcgDiceUeid(boolean critical, TcgUeid value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.tcg_dice_ueid, critical, value);
    extn.tcgDiceUeid = value;
    return extn;
  }

  public static Extension ofCertHash(boolean critical, CertHash value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.isismtt_at_certHash, critical, value);
    extn.certHash = value;
    return extn;
  }

  public static Extension ofMasaUrl(boolean critical, Asn1IA5String value) {
    Args.notNull(value, "value");
    Extension extn = create2(ExtensionOIDs.id_pe_masa_url, critical, value);
    extn.masaUrl = value;
    return extn;
  }

  public static Extension ofMasaUrl(boolean critical, String value) {
    Args.notNull(value, "value");
    return ofMasaUrl(critical, new Asn1IA5String(value));
  }

  public Asn1Oid getExtnId() {
    return extnId;
  }

  public boolean isCritical() {
    return critical;
  }

  public Asn1OctetString getExtnValue() {
    return value;
  }

  public byte[] extnValue() {
    return value.getOctets();
  }

  public void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    String id = extnId.getId();
    byte[] octets = value.getOctets();
    if (id.equals(ExtensionOIDs.subjectDirectoryAttributes.getId())) {
      subjectDirectoryAttributes = SubjectDirectoryAttributes.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.subjectKeyIdentifier.getId())) {
      subjectKeyIdentifier = SubjectKeyIdentifier.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.keyUsage.getId())) {
      keyUsage = KeyUsage.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.privateKeyUsagePeriod.getId())) {
      privateKeyUsagePeriod = PrivateKeyUsagePeriod.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.subjectAlternativeName.getId())) {
      subjectAlternativeName = GeneralNames.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.issuerAlternativeName.getId())) {
      issuerAlternativeName = GeneralNames.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.basicConstraints.getId())) {
      basicConstraints = BasicConstraints.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.cRLNumber.getId())) {
      cRLNumber = Asn1Integer.fromEncodedNonNegative(octets);
    } else if (id.equals(ExtensionOIDs.reasonCode.getId())) {
      reasonCode = CRLReason.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.instructionCode.getId())) {
      instructionCode = Asn1Oid.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.invalidityDate.getId())) {
      invalidityDate = Asn1GeneralizedTime.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.deltaCRLIndicator.getId())) {
      deltaCRLIndicator = Asn1Integer.fromEncodedNonNegative(octets);
    } else if (id.equals(ExtensionOIDs.issuingDistributionPoint.getId())) {
      issuingDistributionPoint = IssuingDistributionPoint.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.certificateIssuer.getId())) {
      certificateIssuer = GeneralNames.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.nameConstraints.getId())) {
      nameConstraints = NameConstraints.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.cRLDistributionPoints.getId())) {
      cRLDistributionPoints = CRLDistributionPoints.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.certificatePolicies.getId())) {
      certificatePolicies = CertificatePolicies.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.policyMappings.getId())) {
      policyMappings = PolicyMappings.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.authorityKeyIdentifier.getId())) {
      authorityKeyIdentifier = AuthorityKeyIdentifier.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.policyConstraints.getId())) {
      policyConstraints = PolicyConstraints.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.extendedKeyUsage.getId())) {
      extendedKeyUsage = ExtendedKeyUsage.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.freshestCRL.getId())) {
      freshestCRL = CRLDistributionPoints.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.inhibitAnyPolicy.getId())) {
      inhibitAnyPolicy = Asn1Integer.fromEncodedNonNegative(octets);
    } else if (id.equals(ExtensionOIDs.authorityInfoAccess.getId())) {
      authorityInfoAccess = AuthorityInfoAccessSyntax.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.subjectInfoAccess.getId())) {
      subjectInfoAccess = SubjectInfoAccessSyntax.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_smimeCapabilities.getId())) {
      smimeCapabilities = SMIMECapabilities.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.biometricInfo.getId())) {
      biometricInfo = BiometricSyntax.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.qCStatements.getId())) {
      qCStatements = QCStatements.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.noRevAvail.getId())) {
      noRevAvail = Asn1Null.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.expiredCertsOnCRL.getId())) {
      expiredCertsOnCRL = Asn1GeneralizedTime.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pkix_ocsp_nocheck.getId())) {
      ocspNoCheck = Asn1Null.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pkix_ocsp_prefSigAlgs.getId())) {
      preferredSignatureAlgorithms = PreferredSignatureAlgorithms.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_precertificate.getId())) {
      preCertificate = Asn1Null.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_SignedCertificateTimestampList.getId())) {
      signedCertificateTimestampList = Asn1OctetString.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.ASIdentifiers.getId())) {
      aSIdentifiers = ASIdentifiers.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.ASIdentifiersV2.getId())) {
      aSIdentifiersV2 = ASIdentifiers.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.IPAddrBlocks.getId())) {
      iPAddrBlocks = IPAddrBlocks.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.IPAddrBlocksV2.getId())) {
      iPAddrBlocksV2 = IPAddrBlocks.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pe_tlsfeature.getId())) {
      tlsFeatures = TLSFeatures.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_dmtf_spdm_extension.getId())) {
      spdmExtension = SpdmCertOids.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_F_External_CA_Cert.getId())) {
      CCC_F_External_CACert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_J_VehicleOEM_CA_Cert.getId())) {
      CCC_J_VehicleOEMCACert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_K_Vehicle_Cert.getId())) {
      CCC_K_VehicleCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_M_VehicleOEM_CA_Cert.getId())) {
      CCC_M_VehicleOEMCACert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_P_VehicleOEM_Enc_Cert.getId())) {
      CCC_P_VehicleOEMEncCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_Q_VehicleOEM_Sig_Cert.getId())) {
      CCC_Q_VehicleOEMSigCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_R_CertificationBody_Cert.getId())) {
      CCC_R_CertificationBodyCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_S_SBxDKis_Intermediate_CA_Cert.getId())) {
      CCC_S_SBxDKisIntermediateCACert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_U_SBxDKis_RootCA_Cert.getId())) {
      CCC_U_SBxDKisRootCACert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_Device_Enc_Cert.getId())) {
      CCC_DeviceEncCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_Vehicle_Intermediate_Cert.getId())) {
      CCC_VehicleIntermediateCert = SimpleExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_E_Instance_CA_Cert.getId())) {
      CCC_E_Instance_CACert = InstanceCACertificateExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_H_Endpoint_Cert.getId())) {
      CCC_H_EndpointCert = EndpointCertificateExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_ccc_T_SBxDKis_Endpoint_Cert.getId())) {
      CCC_T_SBxDKisEndpointCert = SBxDKisCertificateExtensionSchema.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_cn_residentIdCardNumber.getId())) {
      CN_ResidentIdCardNumber = Asn1PrintableString.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_cn_passportNumber.getId())) {
      CN_PassportNumber = Asn1Utf8String.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_cn_socialInsuranceNumber.getId())) {
      CN_SocialInsuranceNumber = Asn1PrintableString.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_cn_unifiedSocialCreditCode.getId())) {
      CN_UnifiedSocialCreditCode = Asn1PrintableString.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pe_TNAuthList.getId())) {
      tNAuthList = TNAuthorizationList.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_microsoft_SecurityIdentifier.getId())) {
      microsoftSecurityIdentifier = GeneralNames.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_microsoft_CertificateTemplateInformation.getId())) {
      microsoftCertificateTemplate = MicrosoftCertificateTemplate.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.tcg_dice_ueid.getId())) {
      tcgDiceUeid = TcgUeid.fromAsn1(Asn1Sequence.fromEncoded(octets));
    } else if (id.equals(ExtensionOIDs.isismtt_at_certHash.getId())) {
      certHash = CertHash.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pkix_ocsp_nonce.getId())) {
      ocspNonce = Asn1OctetString.fromEncoded(octets);
    } else if (id.equals(ExtensionOIDs.id_pe_masa_url.getId())) {
      masaUrl = Asn1IA5String.fromEncoded(octets);
    }

    parsed = true;
  }

  public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
    return subjectDirectoryAttributes;
  }

  public SubjectKeyIdentifier getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public byte[] subjectKeyIdentifier() {
    return subjectKeyIdentifier == null ? null : subjectKeyIdentifier.getKeyIdentifier();
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

  public PrivateKeyUsagePeriod getPrivateKeyUsagePeriod() {
    return privateKeyUsagePeriod;
  }

  public GeneralNames getSubjectAlternativeName() {
    return subjectAlternativeName;
  }

  public GeneralNames getIssuerAlternativeName() {
    return issuerAlternativeName;
  }

  public BasicConstraints getBasicConstraints() {
    return basicConstraints;
  }

  public Asn1Integer getCRLNumber() {
    return cRLNumber;
  }

  public BigInteger cRLNumber() {
    return Asn1Util.fromAsn1(cRLNumber);
  }

  public CRLReason getReasonCode() {
    return reasonCode;
  }

  public Asn1Oid getInstructionCode() {
    return instructionCode;
  }

  public Asn1GeneralizedTime getInvalidityDate() {
    return invalidityDate;
  }

  public Instant invalidityDate() {
    return Asn1Util.fromAsn1(invalidityDate);
  }

  public Asn1Integer getDeltaCRLIndicator() {
    return deltaCRLIndicator;
  }

  public BigInteger deltaCRLIndicator() {
    return Asn1Util.fromAsn1(deltaCRLIndicator);
  }

  public IssuingDistributionPoint getIssuingDistributionPoint() {
    return issuingDistributionPoint;
  }

  public GeneralNames getCertificateIssuer() {
    return certificateIssuer;
  }

  public NameConstraints getNameConstraints() {
    return nameConstraints;
  }

  public CRLDistributionPoints getCRLDistributionPoints() {
    return cRLDistributionPoints;
  }

  public CertificatePolicies getCertificatePolicies() {
    return certificatePolicies;
  }

  public PolicyMappings getPolicyMappings() {
    return policyMappings;
  }

  public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
    return authorityKeyIdentifier;
  }

  public PolicyConstraints getPolicyConstraints() {
    return policyConstraints;
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public CRLDistributionPoints getFreshestCRL() {
    return freshestCRL;
  }

  public Asn1Integer getInhibitAnyPolicy() {
    return inhibitAnyPolicy;
  }

  public Integer inhibitAnyPolicy() {
    return Asn1Util.fromAsn1Int(inhibitAnyPolicy);
  }

  public AuthorityInfoAccessSyntax getAuthorityInfoAccess() {
    return authorityInfoAccess;
  }

  public SubjectInfoAccessSyntax getSubjectInfoAccess() {
    return subjectInfoAccess;
  }

  public SMIMECapabilities getSmimeCapabilities() {
    return smimeCapabilities;
  }
  public BiometricSyntax getBiometricInfo() {
    return biometricInfo;
  }

  public QCStatements getQCStatements() {
    return qCStatements;
  }

  public Asn1Null getNoRevAvail() {
    return noRevAvail;
  }

  public Asn1GeneralizedTime getExpiredCertsOnCRL() {
    return expiredCertsOnCRL;
  }

  public Instant expiredCertsOnCRL() {
    return Asn1Util.fromAsn1(expiredCertsOnCRL);
  }

  public Asn1Null getOcspNoCheck() {
    return ocspNoCheck;
  }

  public Asn1OctetString getOcspNonce() {
    return ocspNonce;
  }

  public byte[] ocspNonce() {
    return Asn1Util.fromAsn1(ocspNonce);
  }

  public PreferredSignatureAlgorithms getPreferredSignatureAlgorithms() {
    return preferredSignatureAlgorithms;
  }

  public Asn1Null getPreCertificate() {
    return preCertificate;
  }

  public Asn1OctetString getSignedCertificateTimestampList() {
    return signedCertificateTimestampList;
  }

  public byte[] signedCertificateTimestampList() {
    return signedCertificateTimestampList == null ? null
        : signedCertificateTimestampList.getOctets();
  }

  public ASIdentifiers getASIdentifiers() {
    return aSIdentifiers;
  }

  public ASIdentifiers getASIdentifiersV2() {
    return aSIdentifiersV2;
  }

  public IPAddrBlocks getIPAddrBlocks() {
    return iPAddrBlocks;
  }

  public IPAddrBlocks getIPAddrBlocksV2() {
    return iPAddrBlocksV2;
  }

  public TLSFeatures getTlsFeatures() {
    return tlsFeatures;
  }

  public SpdmCertOids getSpdmExtension() {
    return spdmExtension;
  }

  public SimpleExtensionSchema getCCC_F_External_CACert() {
    return CCC_F_External_CACert;
  }

  public SimpleExtensionSchema getCCC_J_VehicleOEMCACert() {
    return CCC_J_VehicleOEMCACert;
  }

  public SimpleExtensionSchema getCCC_K_VehicleCert() {
    return CCC_K_VehicleCert;
  }

  public SimpleExtensionSchema getCCC_M_VehicleOEMCACert() {
    return CCC_M_VehicleOEMCACert;
  }

  public SimpleExtensionSchema getCCC_P_VehicleOEMEncCert() {
    return CCC_P_VehicleOEMEncCert;
  }

  public SimpleExtensionSchema getCCC_Q_VehicleOEMSigCert() {
    return CCC_Q_VehicleOEMSigCert;
  }

  public SimpleExtensionSchema getCCC_R_CertificationBodyCert() {
    return CCC_R_CertificationBodyCert;
  }

  public SimpleExtensionSchema getCCC_S_SBxDKisIntermediateCACert() {
    return CCC_S_SBxDKisIntermediateCACert;
  }

  public SimpleExtensionSchema getCCC_U_SBxDKisRootCACert() {
    return CCC_U_SBxDKisRootCACert;
  }

  public SimpleExtensionSchema getCCC_DeviceEncCert() {
    return CCC_DeviceEncCert;
  }

  public SimpleExtensionSchema getCCC_VehicleIntermediateCert() {
    return CCC_VehicleIntermediateCert;
  }

  public InstanceCACertificateExtensionSchema getCCC_E_Instance_CACert() {
    return CCC_E_Instance_CACert;
  }

  public EndpointCertificateExtensionSchema getCCC_H_EndpointCert() {
    return CCC_H_EndpointCert;
  }

  public SBxDKisCertificateExtensionSchema getCCC_T_SBxDKisEndpointCert() {
    return CCC_T_SBxDKisEndpointCert;
  }

  public Asn1PrintableString getCN_ResidentIdCardNumber() {
    return CN_ResidentIdCardNumber;
  }

  public String CN_ResidentIdCardNumber() {
    return Asn1Util.fromAsn1(CN_ResidentIdCardNumber);
  }

  public Asn1Utf8String getCN_PassportNumber() {
    return CN_PassportNumber;
  }

  public String CN_PassportNumber() {
    return Asn1Util.fromAsn1(CN_PassportNumber);
  }

  public Asn1PrintableString getCN_SocialInsuranceNumber() {
    return CN_SocialInsuranceNumber;
  }

  public String CN_SocialInsuranceNumber() {
    return Asn1Util.fromAsn1(CN_SocialInsuranceNumber);
  }

  public Asn1PrintableString getCN_UnifiedSocialCreditCode() {
    return CN_UnifiedSocialCreditCode;
  }

  public String CN_UnifiedSocialCreditCode() {
    return Asn1Util.fromAsn1(CN_UnifiedSocialCreditCode);
  }

  public TNAuthorizationList getTNAuthList() {
    return tNAuthList;
  }

  public GeneralNames getMicrosoftSecurityIdentifier() {
    return microsoftSecurityIdentifier;
  }

  public MicrosoftCertificateTemplate getMicrosoftCertificateTemplate() {
    return microsoftCertificateTemplate;
  }

  public TcgUeid getTcgDiceUeid() {
    return tcgDiceUeid;
  }

  public byte[] tcgDiceUeid() {
    return tcgDiceUeid == null ? null : tcgDiceUeid.ueid();
  }

  public CertHash getCertHash() {
    return certHash;
  }

  public Asn1IA5String getMasaUrl() {
    return masaUrl;
  }

  public String masaUrl() {
    return Asn1Util.fromAsn1(masaUrl);
  }

  private Asn1Encodable parsedExtnValue() {
    if (!parsed) {
      return this.value;
    } else if (subjectDirectoryAttributes != null) {
      return subjectDirectoryAttributes;
    } else if (subjectKeyIdentifier != null) {
      return subjectKeyIdentifier;
    } else if (keyUsage != null) {
      return keyUsage;
    } else if (privateKeyUsagePeriod != null) {
      return privateKeyUsagePeriod;
    } else if (subjectAlternativeName != null) {
      return subjectAlternativeName;
    } else if (issuerAlternativeName != null) {
      return issuerAlternativeName;
    } else if (basicConstraints != null) {
      return basicConstraints;
    } else if (cRLNumber != null) {
      return cRLNumber;
    } else if (reasonCode != null) {
      return reasonCode;
    } else if (instructionCode != null) {
      return instructionCode;
    } else if (invalidityDate != null) {
      return invalidityDate;
    } else if (deltaCRLIndicator != null) {
      return deltaCRLIndicator;
    } else if (issuingDistributionPoint != null) {
      return issuingDistributionPoint;
    } else if (certificateIssuer != null) {
      return certificateIssuer;
    } else if (nameConstraints != null) {
      return nameConstraints;
    } else if (cRLDistributionPoints != null) {
      return cRLDistributionPoints;
    } else if (certificatePolicies != null) {
      return certificatePolicies;
    } else if (policyMappings != null) {
      return policyMappings;
    } else if (authorityKeyIdentifier != null) {
      return authorityKeyIdentifier;
    } else if (policyConstraints != null) {
      return policyConstraints;
    } else if (extendedKeyUsage != null) {
      return extendedKeyUsage;
    } else if (freshestCRL != null) {
      return freshestCRL;
    } else if (inhibitAnyPolicy != null) {
      return inhibitAnyPolicy;
    } else if (authorityInfoAccess != null) {
      return authorityInfoAccess;
    } else if (subjectInfoAccess != null) {
      return subjectInfoAccess;
    } else if (smimeCapabilities != null) {
      return smimeCapabilities;
    } else if (biometricInfo != null) {
      return biometricInfo;
    } else if (qCStatements != null) {
      return qCStatements;
    } else if (noRevAvail != null) {
      return noRevAvail;
    } else if (expiredCertsOnCRL != null) {
      return expiredCertsOnCRL;
    } else if (ocspNoCheck != null) {
      return ocspNoCheck;
    } else if (ocspNonce != null) {
      return ocspNonce;
    } else if (preferredSignatureAlgorithms != null) {
      return preferredSignatureAlgorithms;
    } else if (preCertificate != null) {
      return preCertificate;
    } else if (signedCertificateTimestampList != null) {
      return signedCertificateTimestampList;
    } else if (aSIdentifiers != null) {
      return aSIdentifiers;
    } else if (aSIdentifiersV2 != null) {
      return aSIdentifiersV2;
    } else if (iPAddrBlocks != null) {
      return iPAddrBlocks;
    } else if (iPAddrBlocksV2 != null) {
      return iPAddrBlocksV2;
    } else if (tlsFeatures != null) {
      return tlsFeatures;
    } else if (spdmExtension != null) {
      return spdmExtension;
    } else if (CCC_F_External_CACert != null) {
      return CCC_F_External_CACert;
    } else if (CCC_J_VehicleOEMCACert != null) {
      return CCC_J_VehicleOEMCACert;
    } else if (CCC_K_VehicleCert != null) {
      return CCC_K_VehicleCert;
    } else if (CCC_M_VehicleOEMCACert != null) {
      return CCC_M_VehicleOEMCACert;
    } else if (CCC_P_VehicleOEMEncCert != null) {
      return CCC_P_VehicleOEMEncCert;
    } else if (CCC_Q_VehicleOEMSigCert != null) {
      return CCC_Q_VehicleOEMSigCert;
    } else if (CCC_S_SBxDKisIntermediateCACert != null) {
      return CCC_S_SBxDKisIntermediateCACert;
    } else if (CCC_U_SBxDKisRootCACert != null) {
      return CCC_U_SBxDKisRootCACert;
    } else if (CCC_DeviceEncCert != null) {
      return CCC_DeviceEncCert;
    } else if (CCC_VehicleIntermediateCert != null) {
      return CCC_VehicleIntermediateCert;
    } else if (CCC_E_Instance_CACert != null) {
      return CCC_E_Instance_CACert;
    } else if (CCC_H_EndpointCert != null) {
      return CCC_H_EndpointCert;
    } else if (CCC_T_SBxDKisEndpointCert != null) {
      return CCC_T_SBxDKisEndpointCert;
    } else if (CN_ResidentIdCardNumber != null) {
      return CN_ResidentIdCardNumber;
    } else if (CN_PassportNumber != null) {
      return CN_PassportNumber;
    } else if (CN_SocialInsuranceNumber != null) {
      return CN_SocialInsuranceNumber;
    } else if (CN_UnifiedSocialCreditCode != null) {
      return CN_UnifiedSocialCreditCode;
    } else if (tNAuthList != null) {
      return tNAuthList;
    } else if (microsoftSecurityIdentifier != null) {
      return microsoftSecurityIdentifier;
    } else if (microsoftCertificateTemplate != null) {
      return microsoftCertificateTemplate;
    } else if (tcgDiceUeid != null) {
      return tcgDiceUeid;
    } else if (certHash != null) {
      return certHash;
    } else if (masaUrl != null) {
      return masaUrl;
    } else {
      return value;
    }
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    Asn1Boolean asn1Critical = critical ? Asn1Boolean.TRUE : null;
    return Asn1Sequence.buildIgnoreNull(extnId, asn1Critical, value);
  }

  @Override
  public int hashCode() {
    return extnId.hashCode() * 31 + value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Extension)) {
      return false;
    }

    Extension b = (Extension) obj;
    return extnId.equals(b.extnId) && value.equals(b.value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    extnId.toStringNoLineSep(buf, indentLevel, "extnId");
    if (critical) {
      buf.append(", critical");
    }
    buf.append("\n");

    if (signedCertificateTimestampList != null) {
      CtLog.SerializedSCT sctl = CtLog.SignedCertificateTimestampList.getInstance(
          signedCertificateTimestampList.getOctets()).sctList();
      return sctl.toString(buf, indentLevel + 1);
    } else {
      Asn1Encodable m = parsedExtnValue();
      if (m instanceof AbstractCollection) {
        return ((AbstractCollection<?>) m).toString(buf, indentLevel + 1, false);
      } else {
        return m.toString(buf, indentLevel + 1);
      }
    }
  }

}
