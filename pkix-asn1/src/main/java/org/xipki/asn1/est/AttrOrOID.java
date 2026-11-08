// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.est;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7030:
 * <pre>
 * AttrOrOID ::= CHOICE (
 *     oid OBJECT IDENTIFIER,
 *     attribute Attribute }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AttrOrOID extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<AttrOrOID> {

    public Seq0(AttrOrOID... entries) {
      super(entries);
    }

    public Seq0(List<AttrOrOID> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    @Override
    protected AttrOrOID newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return AttrOrOID.fromAsn1(coll.getObjectAt(index));
    }

    public static Seq0 fromEncoded(byte[] encoded) throws CodecException {
      return fromAsn1(Asn1Sequence.fromEncoded(encoded));
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

  }

  private final Asn1Oid oid;

  private final EstAttribute attribute;

  private AttrOrOID(Asn1Oid oid, EstAttribute attribute) {
    this.oid = oid;
    this.attribute = attribute;
  }

  public static AttrOrOID ofOid(Asn1Oid oid) {
    return new AttrOrOID(Args.notNull(oid, "oid"), null);
  }

  public static AttrOrOID ofAttribute(EstAttribute attribute) {
    return new AttrOrOID(null, Args.notNull(attribute, "attribute"));
  }

  public static AttrOrOID fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Util.readAsn1Object(encoded));
  }

  public static AttrOrOID fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    if (asn1 instanceof Asn1Oid) {
      return ofOid((Asn1Oid) asn1);
    } else if (asn1 instanceof Asn1Sequence) {
      return ofAttribute(EstAttribute.fromAsn1((Asn1Sequence) asn1));
    } else {
      throw new CodecException("unknown ASN.1 class: " + asn1.getClass().getName());
    }
  }

  public Asn1Oid getOid() {
    return oid;
  }

  public EstAttribute getAttribute() {
    return attribute;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return oid != null ? oid : attribute.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (oid != null) {
      return oid.toStringNoLineSep(buf, indentLevel, "oid");
    }

    return attribute.toStringWithLineSep(buf, indentLevel, "attribute");
  }

}
