// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The DistributionPoint object.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint [0] DistributionPointName OPTIONAL,
 *      reasons           [1] ReasonFlags OPTIONAL,
 *      cRLIssuer         [2] GeneralNames OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DistributionPoint extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<DistributionPoint> {

    public Seq1(DistributionPoint... entries) {
      super(entries);
    }

    public Seq1(List<DistributionPoint> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected DistributionPoint newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return DistributionPoint.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final DistributionPointName distributionPoint;
  private final ReasonFlags reasons;
  private final GeneralNames cRLIssuer;

  public static DistributionPoint fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    int index = 0;

    // CHOICE so explicit
    DistributionPointName distributionPoint = seq.isNotTaggedAt(index, 0) ? null
        : DistributionPointName.fromAsn1(seq.getTaggedAt(index++).getExplicitTaggedBase());

    ReasonFlags reasons = seq.isNotTaggedAt(index, 1) ? null
        : ReasonFlags.fromAsn1(seq.getBitStringTaggedAt(index++, false));

    GeneralNames cRLIssuer = seq.isNotTaggedAt(index, 2) ? null
        : GeneralNames.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new DistributionPoint(distributionPoint, reasons, cRLIssuer);
  }

  public DistributionPoint(DistributionPointName distributionPoint,
      ReasonFlags reasons, GeneralNames cRLIssuer) {
    this.distributionPoint = distributionPoint;
    this.reasons = reasons;
    this.cRLIssuer = cRLIssuer;
  }

  public DistributionPointName getDistributionPoint() {
    return distributionPoint;
  }

  public ReasonFlags getReasons() {
    return reasons;
  }

  public GeneralNames getCRLIssuer() {
    return cRLIssuer;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        // as this is a CHOICE it must be explicitly tagged
        (distributionPoint == null) ? null : Asn1TaggedObject.newExplicit(0, distributionPoint),
        (reasons == null) ? null : Asn1TaggedObject.newImplicit(1, reasons),
        (cRLIssuer == null) ? null : Asn1TaggedObject.newImplicit(2, cRLIssuer));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (distributionPoint == null && reasons == null && cRLIssuer == null) {
      return buf;
    }

    if (distributionPoint != null) {
      distributionPoint.toStringWithLineSep(buf, indentLevel, "distributionPoint", true);
    }

    if (reasons != null) {
      reasons.toStringNoLineSep(buf, indentLevel, "reasons", true);
    }

    if (cRLIssuer != null) {
      cRLIssuer.toStringWithLineSep(buf, indentLevel, "cRLIssuer", true);
    }

    return deleteLastNewLine(buf);
  }
}
