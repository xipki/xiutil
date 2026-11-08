// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * The AuthorityKeyIdentifier object.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] IMPLICIT KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] IMPLICIT GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL  }
 *
 *   KeyIdentifier ::= OCTET STRING
 * </pre>
 * Per RFC 5280 sec. 4.2.1.1 the authorityCertIssuer and
 * authorityCertSerialNumber fields MUST both be present or both be absent.
 *
 * @author Lijun Liao (xipki)
 */
public class AuthorityKeyIdentifier extends Asn1Encodable {

  private final Asn1OctetString keyIdentifier;
  private final GeneralNames certIssuer;
  private final Asn1Integer certSerialNumber;

  public static AuthorityKeyIdentifier fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AuthorityKeyIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    int index = 0;
    Asn1OctetString keyIdentifier = seq.isNotTaggedAt(index, 0) ? null
        : seq.getOctetStringTaggedAt(index++, false);
    GeneralNames certIssuer = seq.isNotTaggedAt(index, 1) ? null
        : GeneralNames.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Asn1Integer certSerialNo = seq.isNotTaggedAt(index, 2) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);

    checkIssuerAndSerial(certIssuer, certSerialNo);
    Asn1Util.checkSequenceEnd(index, size);

    return new AuthorityKeyIdentifier(keyIdentifier, certIssuer, certSerialNo);
  }

  private static void checkIssuerAndSerial(GeneralNames certIssuer, Asn1Integer certSerial) {
    if ((certIssuer == null) != (certSerial == null)) {
      throw new IllegalArgumentException("AuthorityKeyIdentifier authorityCertIssuer " +
          "and authorityCertSerialNumber MUST both be present or both be absent");
    }
  }

  public AuthorityKeyIdentifier(GeneralNames name, BigInteger serialNumber) {
    this(null, name, serialNumber);
  }

  public AuthorityKeyIdentifier(byte[] keyIdentifier) {
    this(keyIdentifier, null, null);
  }

  public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames name, BigInteger serialNumber) {
    this(keyIdentifier == null ? null : new Asn1OctetString(keyIdentifier),
        name,
        serialNumber == null ? null : new Asn1Integer(serialNumber));
  }

  public AuthorityKeyIdentifier(
      Asn1OctetString keyIdentifier, GeneralNames name, Asn1Integer serialNumber) {
    checkIssuerAndSerial(name, serialNumber);
    this.keyIdentifier = keyIdentifier;
    this.certIssuer = name;
    this.certSerialNumber = serialNumber;
  }

  public byte[] getKeyIdentifierOctets() {
    return (keyIdentifier != null) ? keyIdentifier.getOctets() : null;
  }

  public Asn1OctetString getKeyIdentifier() {
    return keyIdentifier;
  }

  public GeneralNames getAuthorityCertIssuer() {
    return certIssuer;
  }

  public Asn1Integer getAuthorityCertSerialNumber() {
    return certSerialNumber;
  }

  public byte[] keyIdentifier() {
    return Asn1Util.fromAsn1(keyIdentifier);
  }

  public BigInteger authorityCertSerialNumber() {
    return Asn1Util.fromAsn1(certSerialNumber);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        keyIdentifier == null ? null : Asn1TaggedObject.newImplicit(0, keyIdentifier),
        certIssuer    == null ? null : Asn1TaggedObject.newImplicit(1, certIssuer),
        certSerialNumber == null ? null : Asn1TaggedObject.newImplicit(2, certSerialNumber));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (keyIdentifier != null) {
      keyIdentifier.toStringWithLineSep(buf, indentLevel, "keyIdentifier", true);
    }

    if (certIssuer != null) {
      certIssuer.toStringWithLineSep(buf, indentLevel, "certIssuer", true);
    }

    if (certSerialNumber != null) {
      certSerialNumber.toStringNoLineSep(buf, indentLevel, "certSerialNumber", true);
    }

    return deleteLastNewLine(buf);
  }
}
