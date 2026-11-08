// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * PKCS#7
 * <pre>
 *  SignedData ::= SEQUENCE {
 *      version              Version,
 *      digestAlgorithms     DigestAlgorithmIdentifiers,
 *      contentInfo          ContentInfo,
 *      certificates     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *      crls             [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos          SignerInfos }
 *
 *  ContentInfo ::= SEQUENCE {
 *     contentType     ContentType,
 *     content     [0] EXPLICIT ANY DEFINED BY contentType }
 *
 *  ExtendedCertificatesAndCertificates ::=
 *      SET OF ExtendedCertificateOrCertificate
 *  CertificateRevocationLists ::=
 *      SET OF CertificateRevocationList
 *
 * CertificateSet ::= SET OF CertificateChoices
 * </pre>
 *
 * RFC 5652 (CMS)
 * <pre>
 * SignedData ::= SEQUENCE {
 *     version              CMSVersion,
 *     digestAlgorithms     DigestAlgorithmIdentifiers,
 *     encapContentInfo     EncapsulatedContentInfo,
 *     certificates     [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *     signerInfos          SignerInfos
 *   }
 *
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * SignerInfos ::= SET OF SignerInfo
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *   eContentType ContentType,
 *   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * </pre>
 *
 * <p>
 * The version calculation uses following ruleset from RFC 5652 section 5.1:
 * <pre>
 * IF ((certificates is present) AND
 *    (any certificates with a type of other are present)) OR
 *    ((crls is present) AND
 *    (any crls with a type of other are present))
 * THEN version MUST be 5
 * ELSE
 *    IF (certificates is present) AND
 *       (any version 2 attribute certificates are present)
 *    THEN version MUST be 4
 *    ELSE
 *       IF ((certificates is present) AND
 *          (any version 1 attribute certificates are present)) OR
 *          (any SignerInfo structures are version 3) OR
 *          (encapContentInfo eContentType is other than id-data)
 *       THEN version MUST be 3
 *       ELSE version MUST be 1
 * </pre>
 * <p>
 *
 * @author Lijun Liao (xipki)
 */
public class SignedData extends Asn1Encodable {

  private static final Asn1Integer VERSION_1 = Asn1Integer.ONE;
  private static final Asn1Integer VERSION_3 = Asn1Integer.THREE;
  private static final Asn1Integer VERSION_4 = Asn1Integer.FOUR;
  private static final Asn1Integer VERSION_5 = Asn1Integer.FIVE;

  private final Asn1Integer version;
  private final AlgorithmIdentifier.Set0 digestAlgorithms;
  private final ContentInfo contentInfo;
  private final SignerInfos signerInfos;

  private final CertificateChoice.Set0 certificates;
  private final RevocationInfoChoice.Set0 crls;

  public SignedData(AlgorithmIdentifier.Set0 digestAlgorithms,
                    ContentInfo contentInfo, CertificateChoice.Set0 certificates,
                    RevocationInfoChoice.Set0 crls, SignerInfos signerInfos) {
    this.digestAlgorithms = Args.notNull(digestAlgorithms, "digestAlgorithms");
    this.contentInfo = Args.notNull(contentInfo, "contentInfo");
    this.signerInfos = Args.notNull(signerInfos, "signerInfos");
    this.certificates = certificates;
    this.crls = crls;
    this.version = calculateVersion(contentInfo.getContentType(), certificates, crls, signerInfos);
  }

  public SignedData(Asn1Integer version, AlgorithmIdentifier.Set0 digestAlgorithms,
                    ContentInfo contentInfo, CertificateChoice.Set0 certificates,
                    RevocationInfoChoice.Set0 crls, SignerInfos signerInfos) {
    this.version = Args.notNull(version, "version");
    this.digestAlgorithms = Args.notNull(digestAlgorithms, "digestAlgorithms");
    this.contentInfo = Args.notNull(contentInfo, "contentInfo");
    this.signerInfos = Args.notNull(signerInfos, "signerInfos");
    this.certificates = certificates;
    this.crls = crls;
  }

  private static Asn1Integer calculateVersion(
      Asn1Oid contentOid, CertificateChoice.Set0 certs,
      RevocationInfoChoice.Set0 crls, SignerInfos signerInfos) {
    if (certs != null) {
      if (certs.hasOtherCertificate()) {
        return VERSION_5;
      }
    }

    // no need to check if otherCrl is true
    if (crls != null) {
      if (crls.hasOtherCrl()) {
        return VERSION_5;
      }
    }

    // TODO: add
    boolean attrCertV1Found = false;
    boolean attrCertV2Found = false;

    if (certs != null) {
      if (certs.hasV1AttributeCertificate()) {
        attrCertV1Found = true;
      } else if (certs.hasV2AttributeCertificate()) {
        attrCertV2Found = true;
      }
    }
    if (attrCertV2Found) {
      return VERSION_4;
    }

    if (attrCertV1Found ||
        signerInfos.hasSignerInfoVersion(3) ||
        !CmsOIDs.data.equals(contentOid)) {
      return VERSION_3;
    }

    return VERSION_1;
  }

  public static SignedData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 4, 6);

    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    AlgorithmIdentifier.Set0 digestAlgorithms =
        AlgorithmIdentifier.Set0.fromAsn1(seq.getSetAt(1));
    ContentInfo contentInfo = ContentInfo.fromAsn1(seq.getSequenceAt(2));

    //  *     certificates     [0] IMPLICIT CertificateSet OPTIONAL,
    // *     crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    // *     signerInfos          SignerInfos
    int index = 3;
    CertificateChoice.Set0 certificates = seq.isNotTaggedAt(index, 0) ? null
        : CertificateChoice.Set0.fromAsn1(seq.getSetTaggedAt(index++, false));

    RevocationInfoChoice.Set0 crls = seq.isNotTaggedAt(index, 1) ? null
        : RevocationInfoChoice.Set0.fromAsn1(seq.getSetTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size - 1);
    SignerInfos signerInfos = new SignerInfos(seq.getSetAt(size - 1));

    return new SignedData(version, digestAlgorithms, contentInfo, certificates, crls, signerInfos);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public AlgorithmIdentifier.Set0 getDigestAlgorithms() {
    return digestAlgorithms;
  }

  public ContentInfo getEncapContentInfo() {
    return contentInfo;
  }

  public CertificateChoice.Set0 getCertificates() {
    return certificates;
  }

  public RevocationInfoChoice.Set0 getCRLs() {
    return crls;
  }

  public SignerInfos getSignerInfos() {
    return signerInfos;
  }

  public int version() {
    return version.intValueExact();
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   */
  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        version, digestAlgorithms, contentInfo,
        (certificates == null) ? null : Asn1TaggedObject.newImplicit(0, certificates),
        (crls == null) ? null : Asn1TaggedObject.newImplicit(1, crls),
        signerInfos);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    digestAlgorithms.toStringWithLineSep(buf, indentLevel, "digestAlgorithms", true);
    contentInfo.toStringWithLineSep(buf, indentLevel, "contentInfo", true);

    if (certificates != null) {
      certificates.toStringWithLineSep(buf, indentLevel, "certificates", true);
    }

    if (crls != null) {
      crls.toStringWithLineSep(buf, indentLevel, "crls", true);
    }

    signerInfos.toStringWithLineSep(buf, indentLevel, "signerInfos", true);

    return deleteLastNewLine(buf);
  }

}
