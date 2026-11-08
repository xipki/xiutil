// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 7292:
 * <pre>
 *  CertBag ::= SEQUENCE {
 *      certId    BAG-TYPE.&id   ({CertTypes}),
 *      certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertBag extends Asn1Encodable {

  private final Asn1Oid certId;
  private final Asn1Primitive certValue;

  public static CertBag fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid certId = seq.getOidAt(0);
    Asn1Primitive certValue = seq.getTaggedAt(1, 0).getExplicitBase();
    return new CertBag(certId, certValue);
  }

  public CertBag(Asn1Oid certId, Asn1Primitive certValue) {
    this.certId = Args.notNull(certId, "certId");
    this.certValue = Args.notNull(certValue, "certValue");
  }

  public Asn1Oid getCertId() {
    return certId;
  }

  public Asn1Primitive getCertValue() {
    return certValue;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(certId, Asn1TaggedObject.newExplicit(0, certValue));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certId.toStringNoLineSep(buf, indentLevel, "certId", true);
    certValue.toStringWithLineSep(buf, indentLevel, "certValue", true);

    return deleteLastNewLine(buf);
  }

}
