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
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.5">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * OtherRecipientInfo ::= SEQUENCE {
 *    oriType  OBJECT IDENTIFIER,
 *    oriValue ANY DEFINED BY oriType }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OtherRecipientInfo extends Asn1Encodable {

  private final Asn1Oid oriType;
  private final Asn1Primitive oriValue;

  public OtherRecipientInfo(Asn1Oid oriType, Asn1Primitive oriValue) {
    this.oriType = Args.notNull(oriType, "oriType");
    this.oriValue = Args.notNull(oriValue, "oriValue");
  }

  public static OtherRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid oriType = seq.getOidAt(0);
    Asn1Primitive oriValue = seq.getObjectAt(1);
    return new OtherRecipientInfo(oriType, oriValue);
  }

  public Asn1Oid getType() {
    return oriType;
  }

  public Asn1Primitive getValue() {
    return oriValue;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(oriType, oriValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    oriType.toStringNoLineSep(buf, indentLevel, "oriType", true);
    oriValue.toStringWithLineSep(buf, indentLevel, "oriValue", true);

    return deleteLastNewLine(buf);
  }

}
