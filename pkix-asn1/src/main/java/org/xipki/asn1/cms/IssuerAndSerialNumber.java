// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.4">RFC 5652</a>: IssuerAndSerialNumber object.
 * <p>
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *     issuer       Name,
 *     serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER  -- See RFC 5280
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IssuerAndSerialNumber extends Asn1Encodable {

  private final X500Name name;
  private final Asn1Integer serialNumber;

  public static IssuerAndSerialNumber fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static IssuerAndSerialNumber fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    X500Name name = X500Name.fromAsn1(seq.getSequenceAt(0));
    Asn1Integer serialNumber = seq.getNonNegativeIntegerAt(1);
    return new IssuerAndSerialNumber(name, serialNumber);
  }

  public IssuerAndSerialNumber(Certificate certificate) {
    this.name = Args.notNull(certificate, "certificate").getIssuer();
    this.serialNumber = certificate.getTBSCertificate().getSerialNumber();
  }

  public IssuerAndSerialNumber(X500Name name, BigInteger serialNumber) {
    this.name = Args.notNull(name, "name");
    this.serialNumber = new Asn1Integer(Args.notNull(serialNumber, "serialNumber"));
  }

  public IssuerAndSerialNumber(X500Name name, Asn1Integer serialNumber) {
    this.name = Args.notNull(name, "name");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public X500Name getName() {
    return name;
  }

  public Asn1Integer getSerialNumber() {
    return serialNumber;
  }

  public BigInteger serialNumber() {
    return serialNumber.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(name, serialNumber);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    name.toStringNoLineSep(buf, indentLevel, "name", true);
    serialNumber.toStringNoLineSep(buf, indentLevel, "serialNumber", true);

    return deleteLastNewLine(buf);
  }

}
