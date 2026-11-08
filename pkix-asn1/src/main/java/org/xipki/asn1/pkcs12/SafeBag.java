// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7292 (PKCS#12)
 * <pre>
 *  SafeBag ::= SEQUENCE {
 *      bagId         BAG-TYPE.&id ({PKCS12BagSet}),
 *      bagValue      [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 *      bagAttributes SET OF PKCS12Attribute OPTIONAL
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SafeBag extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<SafeBag> {

    public Seq0(SafeBag... entries) {
      super(entries);
    }

    public Seq0(List<SafeBag> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected SafeBag newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return SafeBag.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid bagId;
  private final Asn1Primitive bagValue;
  private final Attribute.Set0 bagAttributes;

  public SafeBag(Asn1Oid bagId, Asn1Primitive bagValue) {
    this(bagId, bagValue, null);
  }

  public SafeBag(Asn1Oid bagId, Asn1Primitive bagValue, Attribute.Set0 bagAttributes) {
    this.bagId = Args.notNull(bagId, "bagId");
    this.bagValue = Args.notNull(bagValue, "bagValue");
    this.bagAttributes = bagAttributes;
  }

  public static SafeBag fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);

    Asn1Oid bagId = seq.getOidAt(0);
    Asn1Primitive bagValue = seq.getTaggedAt(1, 0).getExplicitBase();
    Attribute.Set0 bagAttributes = (size == 2) ? null : Attribute.Set0.fromAsn1(seq.getSetAt(2));
    return new SafeBag(bagId, bagValue, bagAttributes);
  }

  public Asn1Oid getBagId() {
    return bagId;
  }

  public Asn1Primitive getBagValue() {
    return bagValue;
  }

  public Attribute.Set0 getBagAttributes() {
    return bagAttributes;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(bagId,
        Asn1TaggedObject.newExplicit(0, bagValue), bagAttributes);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    bagId.toStringNoLineSep(buf, indentLevel, "bagId", true);
    bagValue.toStringWithLineSep(buf, indentLevel, "bagValue", true);

    if (bagAttributes != null) {
      bagAttributes.toStringWithLineSep(buf, indentLevel, "bagAttributes", true);
    }

    return deleteLastNewLine(buf);
  }

}
