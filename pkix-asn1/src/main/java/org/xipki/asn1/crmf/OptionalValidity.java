// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.AbstractAsn1Time;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * RFC 4211:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * OptionalValidity ::= SEQUENCE {
 *     notBefore    [0] Time OPTIONAL,
 *     notAfter     [1] Time OPTIONAL } --at least one MUST be present
 *
 * Time ::= CHOICE { ... }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OptionalValidity extends Asn1Encodable {

  private final Time notBefore;
  private final Time notAfter;

  public static OptionalValidity fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);

    int index = 0;

    Time notBefore = seq.isNotTaggedAt(index, 0) ? null
        : Time.fromAsn1((AbstractAsn1Time) seq.getObjectOfExplicitTaggedAt(index++));

    Time notAfter = seq.isNotTaggedAt(index, 1) ? null
        : Time.fromAsn1((AbstractAsn1Time) seq.getObjectOfExplicitTaggedAt(index++));

    Asn1Util.checkSequenceEnd(index, size);
    return new OptionalValidity(notBefore, notAfter);
  }

  public OptionalValidity(Time notBefore, Time notAfter) {
    if (notBefore == null && notAfter == null) {
      throw new IllegalArgumentException(
          "at least one of notBefore and notAfter MUST be present.");
    }

    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  public OptionalValidity(Instant notBefore, Instant notAfter) {
    if (notBefore == null && notAfter == null) {
      throw new IllegalArgumentException(
          "at least one of notBefore and notAfter MUST be present.");
    }

    this.notBefore = (notBefore == null) ? null : new Time(notBefore);
    this.notAfter  = (notAfter == null)  ? null : new Time(notAfter);
  }

  public Time getNotBefore() {
    return notBefore;
  }

  public Time getNotAfter() {
    return notAfter;
  }

  public Instant notBefore() {
    return notBefore.time();
  }

  public Instant notAfter() {
    return notAfter.time();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        notBefore == null ? null : Asn1TaggedObject.newExplicit(0, notBefore),
        notAfter  == null ? null : Asn1TaggedObject.newExplicit(1, notAfter));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (notBefore != null) {
      notBefore.toStringNoLineSep(buf, indentLevel, "notBefore", true);
    }

    if (notAfter != null) {
      notAfter.toStringNoLineSep(buf, indentLevel, "notAfter", true);
    }

    return deleteLastNewLine(buf);
  }

}
