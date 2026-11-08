// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * ASRange.
 * <pre>
 * ASRange ::= SEQUENCE {
 *     min   ASId,
 *     max   ASId }
 *
 * ASId ::= INTEGER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASRange extends Asn1Encodable {

  private final Asn1Integer min;

  private final Asn1Integer max;

  public ASRange(BigInteger min, BigInteger max) {
    this.min = new Asn1Integer(Args.notNull(min, "min"));
    this.max = new Asn1Integer(Args.notNull(max, "max"));
  }

  public ASRange(Asn1Integer min, Asn1Integer max) {
    this.min = Args.notNull(min, "min");
    this.max = Args.notNull(max, "max");
  }

  public static ASRange fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new ASRange(seq.getNonNegativeIntegerAt(0), seq.getNonNegativeIntegerAt(1));
  }

  public Asn1Integer getMin() {
    return min;
  }

  public Asn1Integer getMax() {
    return max;
  }

  public BigInteger min() {
    return min.getValue();
  }

  public BigInteger max() {
    return max.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(min, max);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf, indentLevel, min.getValue() + "-" + max.getValue());
  }

}
