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
 * RFC 5652:
 * <pre>
 * OtherCertificateFormat ::= SEQUENCE {
 *         otherCertFormat  OBJECT IDENTIFIER,
 *         otherCert        ANY DEFINED BY otherCertFormat }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OtherCertificateFormat extends Asn1Encodable {

  private final Asn1Oid otherCertFormat;
  private final Asn1Primitive otherCert;

  public static OtherCertificateFormat fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid otherCertFormat = seq.getOidAt(0);
    Asn1Primitive otherCert = seq.getObjectAt(1);
    return new OtherCertificateFormat(otherCertFormat, otherCert);
  }

  public OtherCertificateFormat(Asn1Oid otherCertFormat, Asn1Primitive otherCert) {
    this.otherCertFormat = Args.notNull(otherCertFormat, "otherCertFormat");
    this.otherCert = Args.notNull(otherCert, "otherCert");
  }

  public Asn1Oid getOtherCertFormat() {
    return otherCertFormat;
  }

  public Asn1Primitive getOtherCert() {
    return otherCert;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(otherCertFormat, otherCert);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    otherCertFormat.toStringNoLineSep(buf, indentLevel, "otherCertFormat", true);
    otherCert.toStringWithLineSep(buf, indentLevel, "otherCert", true);

    return deleteLastNewLine(buf);
  }

}
