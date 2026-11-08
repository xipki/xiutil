// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x500;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.AbstractSet1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * AttributeTypeAndValue ::= SEQUENCE {
 *     type  OBJECT IDENTIFIER,
 *     value ANY DEFINED BY type }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeTypeAndValue extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<AttributeTypeAndValue> {

    public Seq1(AttributeTypeAndValue... entries) {
      super(entries);
    }

    public Seq1(List<AttributeTypeAndValue> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected AttributeTypeAndValue newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AttributeTypeAndValue.fromAsn1(coll.getSequenceAt(index));
    }

  }

  public static class Set1 extends AbstractSet1<AttributeTypeAndValue> {

    public Set1(AttributeTypeAndValue... entries) {
      super(entries);
    }

    public Set1(List<AttributeTypeAndValue> entries) {
      super(entries);
    }

    protected Set1(Asn1Set set) throws CodecException {
      super(set);
    }

    public static Set1 fromAsn1(Asn1Set set) throws CodecException {
      return new Set1(set);
    }

    @Override
    protected AttributeTypeAndValue newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AttributeTypeAndValue.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final Asn1Oid type;
  private final Asn1Primitive value;

  public static AttributeTypeAndValue fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid type = seq.getOidAt(0);
    Asn1Primitive value = seq.getObjectAt(1);
    return new AttributeTypeAndValue(type, value);
  }

  public static AttributeTypeAndValue build(Asn1Oid type, Asn1Encodable value) {
    return new AttributeTypeAndValue(type, value.toAsn1Primitive());
  }

  public AttributeTypeAndValue(Asn1Oid type, Asn1Primitive value) {
    this.type = Args.notNull(type, "type");
    this.value = Args.notNull(value, "value");
  }

  public Asn1Oid getType() {
      return type;
  }

  public Asn1Primitive getValue() {
      return value;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(type, value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    type.toStringNoLineSep(buf, indentLevel, "type", true);
    return (value instanceof AbstractAsn1String)
        ? value.toStringNoLineSep(buf, indentLevel, "value")
        : value.toStringWithLineSep(buf, indentLevel, "value");
  }

  @Override
  public int hashCode() {
    return type.hashCode() * 31 + value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof AttributeTypeAndValue)) {
      return false;
    }

    AttributeTypeAndValue b = (AttributeTypeAndValue) obj;
    return type.equals(b.type) && value.equals(b.value);
  }

}
