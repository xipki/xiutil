// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EnvelopedData object.
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *     version                   CMSVersion,
 *     originatorInfo        [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos            RecipientInfos,
 *     encryptedContentInfo      EncryptedContentInfo,
 *     unprotectedAttrs      [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EnvelopedData extends Asn1Encodable {

  private final Asn1Integer version;
  private final OriginatorInfo originatorInfo;
  private final RecipientInfos recipientInfos;
  private final EncryptedContentInfo encryptedContentInfo;
  private final Attributes unprotectedAttrs;

  public EnvelopedData(
      OriginatorInfo originatorInfo, RecipientInfos recipientInfos,
      EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs) {
    this.originatorInfo = originatorInfo;
    this.recipientInfos = Args.notNull(recipientInfos, "recipientInfos");
    this.encryptedContentInfo = Args.notNull(encryptedContentInfo, "encryptedContentInfo");
    this.unprotectedAttrs = unprotectedAttrs;

    int versionNo = calculateVersion(originatorInfo, recipientInfos, unprotectedAttrs);
    this.version = new Asn1Integer(versionNo);
  }

  private EnvelopedData(
      Asn1Integer version, OriginatorInfo originatorInfo, RecipientInfos recipientInfos,
      EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs) {
    this.version = Args.notNull(version, "version");
    this.originatorInfo = originatorInfo;
    this.recipientInfos = Args.notNull(recipientInfos, "recipientInfos");
    this.encryptedContentInfo = Args.notNull(encryptedContentInfo, "encryptedContentInfo");
    this.unprotectedAttrs = unprotectedAttrs;
  }

  public static EnvelopedData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 5);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);

    int index = 1;
    OriginatorInfo originatorInfo = seq.isNotTaggedAt(index, 0) ? null
        : OriginatorInfo.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    RecipientInfos recipientInfos = new RecipientInfos(seq.getSetAt(index++));
    EncryptedContentInfo encryptedContentInfo =
        EncryptedContentInfo.fromAsn1(seq.getSequenceAt(index++));
    Attributes unprotectedAttrs = seq.isNotTaggedAt(index, 1) ? null
        : Attributes.fromAsn1(seq.getSetTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new EnvelopedData(version, originatorInfo, recipientInfos,
        encryptedContentInfo, unprotectedAttrs);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public OriginatorInfo getOriginatorInfo() {
    return originatorInfo;
  }

  public RecipientInfos getRecipientInfos() {
    return recipientInfos;
  }

  public EncryptedContentInfo getEncryptedContentInfo() {
    return encryptedContentInfo;
  }

  public Attributes getUnprotectedAttrs() {
    return unprotectedAttrs;
  }

  public int version() {
    return version.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version,
        (originatorInfo == null ? null : Asn1TaggedObject.newImplicit(0, originatorInfo)),
        recipientInfos, encryptedContentInfo,
        (unprotectedAttrs == null ? null : Asn1TaggedObject.newImplicit(1, unprotectedAttrs))
    );
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);

    if (originatorInfo != null) {
      originatorInfo.toStringWithLineSep(buf, indentLevel, "originatorInfo", true);
    }

    recipientInfos.toStringWithLineSep(buf, indentLevel, "recipientInfos", true);
    encryptedContentInfo.toStringWithLineSep(buf, indentLevel, "encryptedContentInfo", true);

    if (unprotectedAttrs != null) {
      unprotectedAttrs.toStringWithLineSep(buf, indentLevel, "unprotectedAttrs", true);
    }

    return deleteLastNewLine(buf);
  }

  public static int calculateVersion(
      OriginatorInfo originatorInfo, RecipientInfos recipientInfos,
      Attributes unprotectedAttrs) {
    /*
     * IF (originatorInfo is present) AND
     *    ((any certificates with a type of other are present) OR
     *     (any crls with a type of other are present))
     * THEN version is 4
     */
    if (originatorInfo != null &&
        (originatorInfo.hasOtherCertificate() || originatorInfo.hasOtherCrl())) {
      return 4;
    }

    /*
     * ELSE
     *    IF ((originatorInfo is present) AND
     *       (any version 2 attribute certificates are present)) OR
     *       (any RecipientInfo structures include pwri) OR
     *       (any RecipientInfo structures include ori)
     *    THEN version is 3
     */
    if ((originatorInfo != null && originatorInfo.hasV2AttributeCertificate()) ||
        (recipientInfos != null && recipientInfos.hasPwri()) ||
        (recipientInfos != null && recipientInfos.hasOri())) {
      return 3;
    }

    /*
     *    ELSE
     *       IF (originatorInfo is absent) AND
     *          (unprotectedAttrs is absent) AND
     *          (all RecipientInfo structures are version 0)
     *       THEN version is 0
     */
    if ((originatorInfo == null && unprotectedAttrs == null) &&
        (recipientInfos == null || recipientInfos.allWithVersion(0))) {
      return 0;
    }

    /*
     *      ELSE version is 2
     */
    return 2;
  }

}
