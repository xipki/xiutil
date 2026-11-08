// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 * CommonCriteriaEvaluation ::= SEQUENCE {
 *     cCMeasures                CommonCriteriaMeasures,
 *     cCCertificateNumber       UTF8String (SIZE (1..STRMAX)),
 *     cCCertificateAuthority    UTF8String (SIZE (1..STRMAX)),
 *     evaluationScheme          [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     cCCertificateIssuanceDate [1] IMPLICIT GeneralizedTime OPTIONAL,
 *     cCCertificateExpiryDate   [2] IMPLICIT GeneralizedTime OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CommonCriteriaEvaluation extends Asn1Encodable {

  private final CommonCriteriaMeasures cCMeasures;

  private final Asn1Utf8String cCCertificateNumber;

  private final Asn1Utf8String cCCertificateAuthority;

  private final Asn1Utf8String evaluationScheme;

  private final Asn1GeneralizedTime cCCertificateIssuanceDate;

  private final Asn1GeneralizedTime cCCertificateExpiryDate;

  public CommonCriteriaEvaluation(
      CommonCriteriaMeasures cCMeasures, String cCCertificateNumber,
      String cCCertificateAuthority, String evaluationScheme,
      Instant cCCertificateIssuanceDate, Instant cCCertificateExpiryDate) {
    this(cCMeasures, Asn1Util.toUtf8String(cCCertificateNumber),
        Asn1Util.toUtf8String(cCCertificateAuthority), Asn1Util.toUtf8String(evaluationScheme),
        Asn1Util.toGeneralizedDate(cCCertificateIssuanceDate),
        Asn1Util.toGeneralizedDate(cCCertificateExpiryDate));
  }

  public CommonCriteriaEvaluation(
      CommonCriteriaMeasures cCMeasures, Asn1Utf8String cCCertificateNumber,
      Asn1Utf8String cCCertificateAuthority, Asn1Utf8String evaluationScheme,
      Asn1GeneralizedTime cCCertificateIssuanceDate, Asn1GeneralizedTime cCCertificateExpiryDate) {
    this.cCMeasures = Args.notNull(cCMeasures, "cCMeasures");
    this.cCCertificateNumber = Args.notNull(cCCertificateNumber, "cCCertificateNumber");
    this.cCCertificateAuthority = Args.notNull(cCCertificateAuthority, "cCCertificateAuthority");
    this.evaluationScheme = evaluationScheme;
    this.cCCertificateIssuanceDate = cCCertificateIssuanceDate;
    this.cCCertificateExpiryDate = cCCertificateExpiryDate;
  }

  public CommonCriteriaMeasures getCCMeasures() {
    return cCMeasures;
  }

  public Asn1Utf8String getCCCertificateNumber() {
    return cCCertificateNumber;
  }

  public Asn1Utf8String getCCCertificateAuthority() {
    return cCCertificateAuthority;
  }

  public Asn1Utf8String getEvaluationScheme() {
    return evaluationScheme;
  }

  public Asn1GeneralizedTime getCCCertificateIssuanceDate() {
    return cCCertificateIssuanceDate;
  }

  public Asn1GeneralizedTime getCCCertificateExpiryDate() {
    return cCCertificateExpiryDate;
  }

  public String cCCertificateNumber() {
    return cCCertificateNumber.getString();
  }

  public String cCCertificateAuthority() {
    return cCCertificateAuthority.getString();
  }

  public String evaluationScheme() {
    return Asn1Util.fromAsn1(evaluationScheme);
  }

  public Instant cCCertificateIssuanceDate() {
    return Asn1Util.fromAsn1(cCCertificateIssuanceDate);
  }

  public Instant cCCertificateExpiryDate() {
    return Asn1Util.fromAsn1(cCCertificateExpiryDate);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(cCMeasures, cCCertificateNumber, cCCertificateAuthority,
        (evaluationScheme == null) ? null : Asn1TaggedObject.newImplicit(0, evaluationScheme),
        (cCCertificateIssuanceDate == null) ? null
            : Asn1TaggedObject.newImplicit(1, cCCertificateIssuanceDate),
        (cCCertificateExpiryDate == null) ? null
            : Asn1TaggedObject.newImplicit(2, cCCertificateExpiryDate));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    cCMeasures.toStringWithLineSep(buf, indentLevel, "cCMeasures", true);
    cCCertificateNumber.toStringNoLineSep(buf, indentLevel, "cCCertificateNumber", true);
    cCCertificateAuthority.toStringNoLineSep(buf, indentLevel, "cCCertificateAuthority", true);

    if (evaluationScheme != null) {
      evaluationScheme.toStringNoLineSep(buf, indentLevel, "evaluationScheme", true);
    }

    if (cCCertificateIssuanceDate != null) {
      cCCertificateIssuanceDate.toStringNoLineSep(buf, indentLevel,
          "cCCertificateIssuanceDate", true);
    }

    if (cCCertificateExpiryDate != null) {
      cCCertificateExpiryDate.toStringNoLineSep(buf, indentLevel, "cCCertificateExpiryDate", true);
    }

    return deleteLastNewLine(buf);
  }

  public static CommonCriteriaEvaluation fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CommonCriteriaEvaluation fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 6);
    CommonCriteriaMeasures measures = CommonCriteriaMeasures.fromAsn1(seq.getSequenceAt(0));
    Asn1Utf8String cCCertificateNumber = seq.getUtf8StringAt(1);
    Asn1Utf8String cCCertificateAuthority = seq.getUtf8StringAt(2);

    int index = 3;
    Asn1Utf8String evaluationScheme = seq.isNotTaggedAt(index, 0) ? null
        : seq.getUtf8StringTaggedAt(index++, false);

    Asn1GeneralizedTime cCCertificateIssuanceDate = seq.isNotTaggedAt(index, 1) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, false);

    Asn1GeneralizedTime cCCertificateExpiryDate = seq.isNotTaggedAt(index, 2) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, false);
    Asn1Util.checkSequenceEnd(index, size);

    return new CommonCriteriaEvaluation(measures, cCCertificateNumber, cCCertificateAuthority,
        evaluationScheme, cCCertificateIssuanceDate, cCCertificateExpiryDate);
  }

}
