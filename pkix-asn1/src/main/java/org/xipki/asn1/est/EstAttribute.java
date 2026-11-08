// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.est;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.asn1.x509.Attribute;

/**
 * We define here a new EstAttribute instead using the
 * {@link Attribute} since the Attribute
 * defined in RFC 7030 does not follow the generic mapping
 * between attribute type and value.
 *
 * <pre>
 *    Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *         type   ATTRIBUTE.&id({IOSet}),
 *         values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type}) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EstAttribute extends Asn1Encodable {

  private final Asn1Oid type;

  private final Asn1Set values;

  public EstAttribute(Asn1Oid type, Asn1Set values) {
    this.type = Args.notNull(type, "type");
    this.values = Args.notNull(values, "values");
  }

  public static EstAttribute fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static EstAttribute fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new EstAttribute(seq.getOidAt(0), seq.getSetAt(1));
  }

  public Asn1Oid getType() {
    return type;
  }

  public Asn1Set getValues() {
    return values;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(type, values);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    type.toStringNoLineSep(buf, indentLevel, "type", true);
    values.toStringWithLineSep(buf, indentLevel, "values", true);

    return deleteLastNewLine(buf);
  }

}
