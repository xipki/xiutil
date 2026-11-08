// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * IssuingDistributionPoint ::= SEQUENCE {
 *   distributionPoint          [0] DistributionPointName OPTIONAL,
 *   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
 *   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
 *   onlySomeReasons            [3] ReasonFlags OPTIONAL,
 *   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IssuingDistributionPoint extends Asn1Encodable {

  private final DistributionPointName distributionPoint;

  private final boolean onlyContainsUserCerts;

  private final boolean onlyContainsCACerts;

  private final ReasonFlags onlySomeReasons;

  private final boolean indirectCRL;

  private final boolean onlyContainsAttributeCerts;

  public IssuingDistributionPoint(
      DistributionPointName distributionPoint, boolean onlyContainsUserCerts,
      boolean onlyContainsCACerts, ReasonFlags onlySomeReasons, boolean indirectCRL,
      boolean onlyContainsAttributeCerts) {
    int num = (onlyContainsCACerts ? 1 : 0) + (onlyContainsUserCerts ? 1 : 0) +
              (onlyContainsAttributeCerts ? 1 : 0);
    if (num > 1) {
      throw new IllegalArgumentException("only one of onlyContainsCACerts, " +
          "onlyContainsUserCerts, or onlyContainsAttributeCerts can be true");
    }

    this.distributionPoint = distributionPoint;
    this.indirectCRL = indirectCRL;
    this.onlyContainsAttributeCerts = onlyContainsAttributeCerts;
    this.onlyContainsCACerts = onlyContainsCACerts;
    this.onlyContainsUserCerts = onlyContainsUserCerts;
    this.onlySomeReasons = onlySomeReasons;
  }

  public IssuingDistributionPoint(
      DistributionPointName distributionPoint, boolean indirectCRL,
      boolean onlyContainsAttributeCerts) {
    this(distributionPoint, false, false, null,
        indirectCRL, onlyContainsAttributeCerts);
  }

  public static IssuingDistributionPoint fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static IssuingDistributionPoint fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.notNull(seq, "seq").size();
    int index = 0;

    // CHOICE so explicit
    DistributionPointName distributionPoint = seq.isNotTaggedAt(index, 0) ? null
        : DistributionPointName.fromAsn1(seq.getTaggedAt(index++).getExplicitTaggedBase());

    boolean onlyContainsUserCerts = !seq.isNotTaggedAt(index, 1) &&
        seq.getBooleanTaggedAt(index++, false).isTrue();

    boolean onlyContainsCACerts = !seq.isNotTaggedAt(index, 2) &&
        seq.getBooleanTaggedAt(index++, false).isTrue();

    ReasonFlags onlySomeReasons = seq.isNotTaggedAt(index, 3) ? null
        : ReasonFlags.fromAsn1(seq.getBitStringTaggedAt(index++, false));

    boolean indirectCRL = !seq.isNotTaggedAt(index, 4) &&
        seq.getBooleanTaggedAt(index++, false).isTrue();

    boolean onlyContainsAttributeCerts = !seq.isNotTaggedAt(index, 5) &&
        seq.getBooleanTaggedAt(index++, false).isTrue();

    Asn1Util.checkSequenceEnd(index, size);

    int num = (onlyContainsCACerts ? 1 : 0) + (onlyContainsUserCerts ? 1 : 0) +
              (onlyContainsAttributeCerts ? 1 : 0);
    if (num > 1) {
      throw new CodecException("only one of onlyContainsCACerts, " +
          "onlyContainsUserCerts, or onlyContainsAttributeCerts can be true");
    }

    return new IssuingDistributionPoint(distributionPoint, onlyContainsUserCerts,
        onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);
  }

  public boolean onlyContainsUserCerts() {
    return onlyContainsUserCerts;
  }

  public boolean onlyContainsCACerts() {
    return onlyContainsCACerts;
  }

  public boolean isIndirectCRL() {
    return indirectCRL;
  }

  public boolean onlyContainsAttributeCerts() {
    return onlyContainsAttributeCerts;
  }

  public DistributionPointName getDistributionPoint() {
    return distributionPoint;
  }

  public ReasonFlags getOnlySomeReasons() {
    return onlySomeReasons;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    List<Asn1Encodable> vec = new ArrayList<>(6);

    if (distributionPoint != null) { // CHOICE item so explicitly tagged
      vec.add(Asn1TaggedObject.newExplicit(0, distributionPoint));
    }

    if (onlyContainsUserCerts) {
      vec.add(Asn1TaggedObject.newImplicit(1, Asn1Boolean.TRUE));
    }

    if (onlyContainsCACerts) {
      vec.add(Asn1TaggedObject.newImplicit(2, Asn1Boolean.TRUE));
    }

    if (onlySomeReasons != null) {
      vec.add(Asn1TaggedObject.newImplicit(3, onlySomeReasons));
    }

    if (indirectCRL) {
        vec.add(Asn1TaggedObject.newImplicit(4, Asn1Boolean.TRUE));
    }

    if (onlyContainsAttributeCerts) {
        vec.add(Asn1TaggedObject.newImplicit(5, Asn1Boolean.TRUE));
    }

    return new Asn1Sequence(vec);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (distributionPoint != null) {
      distributionPoint.toStringWithLineSep(buf, indentLevel, "distributionPoint", true);
    }

    ToStringUtil.appendIndent(buf, indentLevel,
        "onlyContainsUserCerts: " + onlyContainsUserCerts + "\n");
    ToStringUtil.appendIndent(buf, indentLevel,
        "onlyContainsCACerts: " + onlyContainsCACerts + "\n");

    if (onlySomeReasons != null) {
      onlySomeReasons.toStringNoLineSep(buf, indentLevel, "onlySomeReasons", true);
    }

    ToStringUtil.appendIndent(buf, indentLevel, "indirectCRL: " + indirectCRL + "\n");
    ToStringUtil.appendIndent(buf, indentLevel,
        "onlyContainsAttributeCerts: " + onlyContainsAttributeCerts + "\n");

    return deleteLastNewLine(buf);
  }

}
