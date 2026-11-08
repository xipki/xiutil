// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.cms.IssuerAndSerialNumber;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * From RFC 2875 for Diffie-Hellman POP.
 * <pre>
 * DhSigStatic ::= SEQUENCE {
 *     IssuerAndSerial IssuerAndSerialNumber OPTIONAL,
 *     hashValue       MessageDigest
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DhSigStatic extends Asn1Encodable {

  private final IssuerAndSerialNumber issuerAndSerial;
  private final Asn1OctetString hashValue;

  public DhSigStatic(byte[] hashValue) {
    this(null, hashValue);
  }

  public DhSigStatic(IssuerAndSerialNumber issuerAndSerial, byte[] hashValue) {
    this.issuerAndSerial = issuerAndSerial;
    this.hashValue = new Asn1OctetString(Args.notNull(hashValue, "hashValue"));
  }

  public DhSigStatic(IssuerAndSerialNumber issuerAndSerial, Asn1OctetString hashValue) {
    this.issuerAndSerial = issuerAndSerial;
    this.hashValue = Args.notNull(hashValue, "hashValue");
  }

  public static DhSigStatic fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static DhSigStatic fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    IssuerAndSerialNumber issuerAndSerial = (size == 1) ? null
        : IssuerAndSerialNumber.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString hashValue = seq.getOctetStringAt(size - 1);
    return new DhSigStatic(issuerAndSerial, hashValue);
  }

  public IssuerAndSerialNumber getIssuerAndSerial() {
    return issuerAndSerial;
  }

  public Asn1OctetString getHashValue() {
    return hashValue;
  }

  public byte[] hashValue() {
    return hashValue.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(issuerAndSerial, hashValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (issuerAndSerial != null) {
      issuerAndSerial.toStringWithLineSep(buf, indentLevel, "issuerAndSerial", true);
    }

    hashValue.toStringWithLineSep(buf, indentLevel, "hashValue", true);

    return deleteLastNewLine(buf);
  }

}
