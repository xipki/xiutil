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
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.1">RFC 5652</a>: OtherRevocationInfoFormat object.
 * <p>
 * <pre>
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *      otherRevInfoFormat  OBJECT IDENTIFIER,
 *      otherRevInfo        ANY DEFINED BY otherRevInfoFormat }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OtherRevocationInfoFormat extends Asn1Encodable {

  private final Asn1Oid otherRevInfoFormat;
  private final Asn1Primitive otherRevInfo;

  public OtherRevocationInfoFormat(Asn1Oid otherRevInfoFormat, Asn1Primitive otherRevInfo) {
    this.otherRevInfoFormat = Args.notNull(otherRevInfoFormat, "otherRevInfoFormat");
    this.otherRevInfo = Args.notNull(otherRevInfo, "otherRevInfo");
  }

  public static OtherRevocationInfoFormat fromAsn1(Asn1Sequence seq) throws CodecException {
    Asn1Oid otherRevInfoFormat = seq.getOidAt(0);
    Asn1Primitive otherRevInfo = seq.getObjectAt(1);
    return new OtherRevocationInfoFormat(otherRevInfoFormat, otherRevInfo);
  }

  public Asn1Oid getInfoFormat() {
    return otherRevInfoFormat;
  }

  public Asn1Primitive getInfo() {
    return otherRevInfo;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(otherRevInfoFormat, otherRevInfo);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    otherRevInfoFormat.toStringNoLineSep(buf, indentLevel, "otherRevInfoFormat", true);
    otherRevInfo.toStringWithLineSep(buf, indentLevel, "otherRevInfo", true);

    return deleteLastNewLine(buf);
  }
}
