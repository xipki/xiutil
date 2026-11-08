// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * CertID          ::=     SEQUENCE {
 *     hashAlgorithm       AlgorithmIdentifier,
 *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
 *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
 *     serialNumber        CertificateSerialNumber }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertID extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlgorithm;
  private final Asn1OctetString issuerNameHash;
  private final Asn1OctetString issuerKeyHash;
  private final Asn1Integer serialNumber;

  public CertID(AlgorithmIdentifier hashAlgorithm, Asn1OctetString issuerNameHash,
                Asn1OctetString issuerKeyHash, Asn1Integer serialNumber) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.issuerNameHash = Args.notNull(issuerNameHash, "issuerNameHash");
    this.issuerKeyHash = Args.notNull(issuerKeyHash, "issuerKeyHash");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public static CertID fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 4);

    AlgorithmIdentifier hashAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString issuerNameHash = seq.getOctetStringAt(1);
    Asn1OctetString issuerKeyHash = seq.getOctetStringAt(2);
    Asn1Integer serialNumber = seq.getNonNegativeIntegerAt(3);
    return new CertID(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber);
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public Asn1OctetString getIssuerNameHash() {
    return issuerNameHash;
  }

  public Asn1OctetString getIssuerKeyHash() {
    return issuerKeyHash;
  }

  public Asn1Integer getSerialNumber() {
    return serialNumber;
  }

  public byte[] issuerNameHash() {
    return issuerNameHash.getOctets();
  }

  public byte[] issuerKeyHash() {
    return issuerKeyHash.getOctets();
  }

  public BigInteger serialNumber() {
    return serialNumber.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    issuerNameHash.toStringWithLineSep(buf, indentLevel, "issuerNameHash", true);
    issuerKeyHash.toStringWithLineSep(buf, indentLevel, "issuerKeyHash", true);
    serialNumber.toStringNoLineSep(buf, indentLevel, "serialNumber", true);

    return deleteLastNewLine(buf);
  }

  @Override
  public int hashCode() {
    return hashAlgorithm.hashCode() * 31 * 31 * 31 + issuerNameHash.hashCode() * 31 * 31
        + issuerKeyHash.hashCode() * 31 + serialNumber.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof CertID)) {
      return false;
    }

    CertID b = (CertID) obj;
    return hashAlgorithm.equals(b.hashAlgorithm)
        && issuerKeyHash.equals(b.issuerKeyHash)
        && issuerNameHash.equals(b.issuerNameHash)
        && serialNumber.equals(b.serialNumber);
  }

}
