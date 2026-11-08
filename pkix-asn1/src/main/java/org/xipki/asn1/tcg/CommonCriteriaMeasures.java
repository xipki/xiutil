// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * CommonCriteriaMeasures ::= SEQUENCE {
 *     Version            IA5STRING (SIZE (1..STRMAX)),
 *                            -- “2.2” or “3.1”; future syntax defined by CC
 *     Assurancelevel     EvaluationAssuranceLevel,
 *     evaluationStatus   EvaluationStatus,
 *     plus               BOOLEAN DEFAULT FALSE,
 *     strengthOfFunction [0] IMPLICIT StrengthOfFunction OPTIONAL,
 *     profileOid         [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
 *     profileUri         [2] IMPLICIT URIReference OPTIONAL,
 *     targetOid          [3] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
 *     targetUri          [4] IMPLICIT URIReference OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CommonCriteriaMeasures extends Asn1Encodable {

  private final Asn1IA5String version;

  private final EvaluationAssuranceLevel assuranceLevel;

  private final EvaluationStatus evaluationStatus;

  private final boolean plus;

  private final StrengthOfFunction strengthOfFunction;

  private final Asn1Oid profileOid;

  private final URIReference profileUri;

  private final Asn1Oid targetOid;

  private final URIReference targetUri;

  public CommonCriteriaMeasures(
      String version, EvaluationAssuranceLevel assuranceLevel,
      EvaluationStatus evaluationStatus, boolean plus,
      StrengthOfFunction strengthOfFunction, Asn1Oid profileOid,
      URIReference profileUri, Asn1Oid targetOid, URIReference targetUri) {
    this(Asn1Util.toIA5String(version), assuranceLevel, evaluationStatus, plus,
        strengthOfFunction, profileOid, profileUri, targetOid, targetUri);
  }

  public CommonCriteriaMeasures(
      Asn1IA5String version, EvaluationAssuranceLevel assuranceLevel,
      EvaluationStatus evaluationStatus, boolean plus,
      StrengthOfFunction strengthOfFunction, Asn1Oid profileOid,
      URIReference profileUri, Asn1Oid targetOid, URIReference targetUri) {
    this.version = Args.notNull(version, "version");
    Args.lengthRange(version.getString(), "version", 1, TcgConstants.STRMAX);
    this.assuranceLevel = Args.notNull(assuranceLevel, "assuranceLevel");
    this.evaluationStatus = Args.notNull(evaluationStatus, "evaluationStatus");
    this.plus = plus;
    this.strengthOfFunction = strengthOfFunction;
    this.profileOid = profileOid;
    this.profileUri = profileUri;
    this.targetOid = targetOid;
    this.targetUri = targetUri;
  }

  public Asn1IA5String getVersion() {
    return version;
  }

  public EvaluationAssuranceLevel getAssuranceLevel() {
    return assuranceLevel;
  }

  public EvaluationStatus getEvaluationStatus() {
    return evaluationStatus;
  }

  public boolean isPlus() {
    return plus;
  }

  public StrengthOfFunction getStrengthOfFunction() {
    return strengthOfFunction;
  }

  public Asn1Oid getProfileOid() {
    return profileOid;
  }

  public URIReference getProfileUri() {
    return profileUri;
  }

  public Asn1Oid getTargetOid() {
    return targetOid;
  }

  public URIReference getTargetUri() {
    return targetUri;
  }

  public String version() {
    return version.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, assuranceLevel, evaluationStatus,
        plus ? Asn1Boolean.TRUE : null,
        (strengthOfFunction == null) ? null : Asn1TaggedObject.newImplicit(0, strengthOfFunction),
        (profileOid == null) ? null : Asn1TaggedObject.newImplicit(1, profileOid),
        (profileUri == null) ? null : Asn1TaggedObject.newImplicit(2, profileUri),
        (targetOid  == null) ? null : Asn1TaggedObject.newImplicit(3, targetOid),
        (targetUri  == null) ? null : Asn1TaggedObject.newImplicit(4, targetUri));
  }

  public static CommonCriteriaMeasures fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 9);

    Asn1IA5String version = seq.getIA5StringAt(0);
    EvaluationAssuranceLevel assuranceLevel = EvaluationAssuranceLevel.fromAsn1(
        seq.getEnumeratedAt(1));
    EvaluationStatus evaluationStatus = EvaluationStatus.fromAsn1(seq.getEnumeratedAt(2));

    int index = 3;
    boolean plus = seq.hasBoolean(index) ? seq.getBooleanAt(index++).isTrue() : false;

    // *     strengthOfFunction [0] IMPLICIT StrengthOfFunction OPTIONAL,
    StrengthOfFunction strengthOfFunction = seq.isNotTaggedAt(index, 0) ? null
        : StrengthOfFunction.fromAsn1(seq.getEnumeratedTaggedAt(index++, false));

    // *     profileOid         [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
    Asn1Oid profileOid = seq.isNotTaggedAt(index, 1) ? null
        : seq.getOidTaggedAt(index++, false);

    // *     profileUri         [2] IMPLICIT URIReference OPTIONAL,
    URIReference profileUri = seq.isNotTaggedAt(index, 2) ? null
         : URIReference.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    // *     targetOid          [3] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
    Asn1Oid targetOid = seq.isNotTaggedAt(index, 3) ? null
        : seq.getOidTaggedAt(index++, false);

    // *     targetUri          [4] IMPLICIT URIReference OPTIONAL
    URIReference targetUri = seq.isNotTaggedAt(index, 4) ? null
         : URIReference.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new CommonCriteriaMeasures(version, assuranceLevel, evaluationStatus, plus,
        strengthOfFunction, profileOid, profileUri, targetOid, targetUri);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    assuranceLevel.toStringNoLineSep(buf, indentLevel, "assuranceLevel", true);
    evaluationStatus.toStringNoLineSep(buf, indentLevel, "evaluationStatus", true);
    ToStringUtil.appendIndent(buf, indentLevel, "plus: " + plus + "\n");

    if (strengthOfFunction != null) {
      strengthOfFunction.toStringNoLineSep( buf, indentLevel, "strengthOfFunction", false);
    }

    if (profileOid != null) {
      profileOid.toStringNoLineSep(buf, indentLevel, "profileOid", true);
    }

    if (profileUri != null) {
      profileUri.toStringNoLineSep(buf, indentLevel, "profileUri", true);
    }

    if (targetOid != null) {
      targetOid.toStringNoLineSep(buf, indentLevel, "targetOid", true);
    }

    if (targetUri != null) {
      targetUri.toStringNoLineSep(buf, indentLevel, "targetUri", true);
    }

    return deleteLastNewLine(buf);
  }
}
