// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * ASId Or Range.
 * <pre>
 *  ASIdOrRange         ::= CHOICE {
 *      id                  ASId,
 *      range               ASRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdOrRange extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<ASIdOrRange> {

    public Seq0(ASIdOrRange... entries) {
      super(entries);
    }

    public Seq0(List<ASIdOrRange> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected ASIdOrRange newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return ASIdOrRange.fromAsn1(coll.getObjectAt(index));
    }
  }

  private final Asn1Integer id;

  private final ASRange range;

  private ASIdOrRange(Asn1Integer id, ASRange range) {
    this.id = id;
    this.range = range;
  }

  public static ASIdOrRange fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1Integer) {
      return ofId(Asn1Integer.checkNonNegative((Asn1Integer) asn1));
    } else {
      return ofRange(ASRange.fromAsn1(asn1.asSequence()));
    }
  }

  public static ASIdOrRange ofId(BigInteger id) {
    return new ASIdOrRange(new Asn1Integer(Args.notNull(id, "id")), null);
  }

  public static ASIdOrRange ofId(Asn1Integer id) {
    return new ASIdOrRange(Args.notNull(id, "id"), null);
  }

  public static ASIdOrRange ofRange(ASRange range) {
    return new ASIdOrRange(null, Args.notNull(range, "range"));
  }

  public Asn1Integer getId() {
    return id;
  }

  public ASRange getRange() {
    return range;
  }

  public BigInteger id() {
    return Asn1Util.fromAsn1(id);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return id != null ? id : range.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (id != null) {
      return id.toStringNoLineSep(buf, indentLevel, "id");
    } else {
      return range.toStringNoLineSep(buf, indentLevel, "range");
    }
  }
}
