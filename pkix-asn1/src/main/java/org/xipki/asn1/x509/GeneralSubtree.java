// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Class for containing a restriction object subtrees in NameConstraints. See
 * RFC 3280.
 *
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * GeneralSubtree ::= SEQUENCE {
 *     base            GeneralName,
 *     minimum [0]     BaseDistance DEFAULT 0,
 *     maximum [1]     BaseDistance OPTIONAL
 *  }
 * </pre>
 *
 * @see NameConstraints
 *
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralSubtree extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<GeneralSubtree> {

    public Seq1(GeneralSubtree... entries) {
      super(entries);
    }

    public Seq1(List<GeneralSubtree> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static GeneralSubtree.Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new GeneralSubtree.Seq1(seq);
    }

    @Override
    protected GeneralSubtree newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return GeneralSubtree.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final GeneralName base;

  private final Asn1Integer minimum;

  private final Asn1Integer maximum;

  public static GeneralSubtree fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    GeneralName base = GeneralName.fromAsn1(seq.getTaggedAt(0));
    int index = 1;
    Asn1Integer minimum = seq.isNotTaggedAt(index, 0) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    minimum = minimum != null && minimum.hasValue(0) ? null : minimum;
    Asn1Integer maximum = seq.isNotTaggedAt(index, 1) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    Asn1Util.checkSequenceEnd(index, size);

    return new GeneralSubtree(base, minimum, maximum);
  }

  public GeneralSubtree(GeneralName base, Asn1Integer minimum, Asn1Integer maximum) {
    this.base = Args.notNull(base, "base");
    this.minimum = (minimum == null || minimum.hasValue(0)) ? Asn1Integer.ZERO : minimum;
    this.maximum = maximum;
  }

  public GeneralSubtree(GeneralName base, int minimum, Integer maximum) {
    this(base, new Asn1Integer(minimum), Asn1Util.toInteger(maximum));
  }

  public GeneralSubtree(GeneralName base) {
    this(base, null, null);
  }

  public GeneralName getBase() {
    return base;
  }

  public Asn1Integer getMinimum() {
    return minimum;
  }

  public int minimum() {
    return minimum.intValueExact();
  }

  public Asn1Integer getMaximum() {
    return maximum;
  }

  public Integer maximum() {
    return Asn1Util.fromAsn1Int(maximum);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(base,
        minimum.hasValue(0) ? null
          : Asn1TaggedObject.newImplicit(0, minimum),
        maximum == null ? null : Asn1TaggedObject.newImplicit(1, maximum));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    base.toStringWithLineSep(buf, indentLevel, "base", true);
    minimum.toStringNoLineSep(buf, indentLevel, "minmum", true);
    if (maximum != null) {
      maximum.toStringNoLineSep(buf, indentLevel, "maximum", true);
    }
    return deleteLastNewLine(buf);
  }

}
