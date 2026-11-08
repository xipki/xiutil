// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 * Validity ::= SEQUENCE {
 *   notBefore      Time,
 *   notAfter       Time  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Validity extends Asn1Encodable {

  private final Time notBefore;
  private final Time notAfter;

  public static Validity fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Time notBefore = Time.fromAsn1(seq.getTimeAt(0));
    Time notAfter  = Time.fromAsn1(seq.getTimeAt(1));
    return new Validity(notBefore, notAfter);
  }

  public Validity(Time notBefore, Time notAfter) {
    this.notBefore = Args.notNull(notBefore, "notBefore");
    this.notAfter = Args.notNull(notAfter, "notAfter");
  }

  public Validity(Instant notBefore, Instant notAfter) {
    this.notBefore = new Time(Args.notNull(notBefore, "notBefore"));
    this.notAfter = new Time(Args.notNull(notAfter, "notAfter"));
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
    return new Asn1Sequence(notBefore, notAfter);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    notBefore.toStringNoLineSep(buf, indentLevel, "notBefore", true);
    return notAfter.toStringNoLineSep(buf, indentLevel, "notAfter");
  }

}
