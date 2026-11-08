// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 *   DEFINITIONS IMPLICIT TAGS ::=
 *
 *   PrivateKeyUsagePeriod ::= SEQUENCE {
 *      notBefore       [0]    GeneralizedTime OPTIONAL,
 *      notAfter        [1]    GeneralizedTime OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PrivateKeyUsagePeriod extends Asn1Encodable {

  private final Asn1GeneralizedTime notBefore;

  private final Asn1GeneralizedTime notAfter;

  public static PrivateKeyUsagePeriod fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PrivateKeyUsagePeriod fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);
    int index = 0;
    Asn1GeneralizedTime notBefore = seq.isNotTaggedAt(index, 0) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, false);
    Asn1GeneralizedTime notAfter = seq.isNotTaggedAt(index, 1) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, false);
    Asn1Util.checkSequenceEnd(index, size);
    return new PrivateKeyUsagePeriod(notBefore, notAfter);
  }

  public PrivateKeyUsagePeriod(Asn1GeneralizedTime notBefore, Asn1GeneralizedTime notAfter) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  public PrivateKeyUsagePeriod(Instant notBefore, Instant notAfter) {
    this.notBefore = notBefore != null ? new Asn1GeneralizedTime(notBefore) : null;
    this.notAfter = notAfter != null ? new Asn1GeneralizedTime(notAfter) : null;
  }

  public Asn1GeneralizedTime getNotBefore() {
    return notBefore;
  }

  public Asn1GeneralizedTime getNotAfter() {
    return notAfter;
  }

  public Instant notBefore() {
    return Asn1Util.fromAsn1(notBefore);
  }

  public Instant notAfter() {
    return Asn1Util.fromAsn1(notAfter);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        (notBefore == null) ? null : Asn1TaggedObject.newImplicit(0, notBefore),
        (notAfter  == null) ? null : Asn1TaggedObject.newImplicit(1, notAfter));
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
