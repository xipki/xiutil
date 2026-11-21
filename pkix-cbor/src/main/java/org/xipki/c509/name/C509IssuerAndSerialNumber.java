// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents the issuer and certificate serial number fields of {@code DhSigStaticType}
 * (draft-ietf-cose-cbor-encoded-cert-21, Section 4.2).
 *
 * <pre>
 * DhSigStatic = MessageDigest / DhSigStaticType
 * MessageDigest = bytes
 * DhSigStaticType = [
 *   issuer: Name,
 *   certificateSerialNumber: CertificateSerialNumber,
 *   hashValue: MessageDigest,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class C509IssuerAndSerialNumber extends CborEncodable {

  private final C509Name issuer;

  private final BigInteger serialNumber;

  public C509IssuerAndSerialNumber(C509Name issuer, BigInteger serialNumber) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public C509Name issuer() {
    return issuer;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2);
    issuer.encode(encoder);
    encoder.writeUnwrappedBiguint(serialNumber);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuer.toStringNoLineSep(buf, indentLevel, "Issuer", true);
    ToStringUtil.appendIndent(buf, indentLevel, "Serial Number:\n");
    return ToStringUtil.appendBigInt(buf, indentLevel + 1, serialNumber);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509IssuerAndSerialNumber)) {
      return false;
    }

    C509IssuerAndSerialNumber b = (C509IssuerAndSerialNumber) obj;

    return Objects.equals(serialNumber, b.serialNumber) && Objects.equals(issuer, b.issuer);
  }
  @Override
  public int hashCode() {
    return Objects.hash(serialNumber, issuer);
  }

  public static C509IssuerAndSerialNumber parse(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return read(decoder);
    }
  }

  public static C509IssuerAndSerialNumber read(CborDecoder decoder) throws CodecException {
    decoder.readArrayLength(2);
    C509Name issuer = C509Name.read(decoder);
    BigInteger serialNumber = decoder.readUnwrappedBigInt();
    return new C509IssuerAndSerialNumber(issuer, serialNumber);
  }

}
