// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 *  IssuerSerial  ::=  SEQUENCE {
 *      issuer         GeneralNames,
 *      serial         CertificateSerialNumber,
 *      issuerUID      UniqueIdentifier OPTIONAL
 *  }
 *
 * UniqueIdentifier  ::=  BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IssuerSerial extends Asn1Encodable {

  private final GeneralNames issuer;
  private final Asn1Integer serial;
  private final Asn1BitString issuerUID;

  public static IssuerSerial fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);

    GeneralNames issuer = GeneralNames.fromAsn1(seq.getSequenceAt(0));
    Asn1Integer serial = seq.getNonNegativeIntegerAt(1);
    Asn1BitString issuerUID = (size == 3) ? seq.getBitStringAt(2) : null;
    return new IssuerSerial(issuer, serial, issuerUID);
  }

  public IssuerSerial(X500Name issuer, BigInteger serial) {
    this(new GeneralNames(GeneralName.ofDirectoryName(issuer)), new Asn1Integer(serial));
  }

  public IssuerSerial(GeneralNames issuer, BigInteger serial) {
    this(issuer, new Asn1Integer(serial));
  }

  public IssuerSerial(GeneralNames issuer, Asn1Integer serial) {
    this(issuer, serial, null);
  }

  public IssuerSerial(GeneralNames issuer, Asn1Integer serial, Asn1BitString issuerUID) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.serial = Args.notNull(serial, "serial");
    this.issuerUID = issuerUID;
  }

  public GeneralNames getIssuer() {
    return issuer;
  }

  public Asn1Integer getSerial() {
    return serial;
  }

  public Asn1BitString getIssuerUID() {
    return issuerUID;
  }

  public BigInteger serial() {
    return serial.getValue();
  }

  public byte[] issuerUID() {
    return Asn1Util.fromAsn1(issuerUID);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(issuer, serial, issuerUID);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuer.toStringWithLineSep(buf, indentLevel, "issuer", true);
    serial.toStringNoLineSep(buf, indentLevel, "serial", true);
    if (issuerUID != null) {
      issuerUID.toStringNoLineSep(buf, indentLevel, "issuerUID", true);
    }
    return deleteLastNewLine(buf);
  }
}
