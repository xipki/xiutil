// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>:
 * OtherKeyAttribute object.
 * <p>
 * <pre>
 * OtherKeyAttribute ::= SEQUENCE {
 *     keyAttrId  OBJECT IDENTIFIER,
 *     keyAttr    ANY DEFINED BY keyAttrId OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OtherKeyAttribute extends Asn1Encodable {

  private final Asn1Oid keyAttrId;
  private final Asn1Primitive keyAttr;

  public static OtherKeyAttribute fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid keyAttrId = seq.getOidAt(0);
    Asn1Primitive keyAttr = (size == 1) ? null : seq.getObjectAt(1);
    return new OtherKeyAttribute(keyAttrId, keyAttr);
  }

  public OtherKeyAttribute(Asn1Oid keyAttrId, Asn1Primitive keyAttr) {
    this.keyAttrId = Args.notNull(keyAttrId, "keyAttrId");
    this.keyAttr = keyAttr;
  }

  public Asn1Oid getKeyAttrId() {
    return keyAttrId;
  }

  public Asn1Primitive getKeyAttr() {
    return keyAttr;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(keyAttrId, keyAttr);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    keyAttrId.toStringNoLineSep(buf, indentLevel, "keyAttrId", true);

    if (keyAttr != null) {
      keyAttr.toStringWithLineSep(buf, indentLevel, "keyAttr", true);
    }

    return deleteLastNewLine(buf);
  }

}
