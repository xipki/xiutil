// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.asn1.x509.IssuerSerial;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * CertificateIdentifierTrait TRAIT ::= {
 *     SYNTAX CertificateIdentifier
 *     IDENTIFIED BY tcg-tr-ID-certificateIdentifier
 * }
 *
 * CertificateIdentifier ::= SEQUENCE {
 *     hashedCertIdentifier  [0] IMPLICIT HashedCertificateIdentifier OPTIONAL,
 *     genericCertIdentifier [1] IMPLICIT IssuerSerial OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateIdentifier extends Asn1Encodable {

  private final HashedCertificateIdentifier hashedCertIdentifier;

  private final IssuerSerial genericCertIdentifier;

  public CertificateIdentifier(HashedCertificateIdentifier hashedCertIdentifier,
                               IssuerSerial genericCertIdentifier) {
    if (hashedCertIdentifier == null && genericCertIdentifier == null) {
      throw new IllegalArgumentException(
          "hashedCertIdentifier and genericCertIdentifier must not be both null");
    }

    this.hashedCertIdentifier = hashedCertIdentifier;
    this.genericCertIdentifier = genericCertIdentifier;
  }

  public HashedCertificateIdentifier getHashedCertIdentifier() {
    return hashedCertIdentifier;
  }

  public IssuerSerial getGenericCertIdentifier() {
    return genericCertIdentifier;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        hashedCertIdentifier == null ? null
            : Asn1TaggedObject.newImplicit(0, hashedCertIdentifier),
        genericCertIdentifier == null ? null
            : Asn1TaggedObject.newImplicit(1, genericCertIdentifier));
  }

  public static CertificateIdentifier fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertificateIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;

    HashedCertificateIdentifier hashedCertIdentifier = seq.isNotTaggedAt(index, 0) ? null
        : HashedCertificateIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    IssuerSerial genericCertIdentifier = seq.isNotTaggedAt(index, 1) ? null
            : IssuerSerial.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Asn1Util.checkSequenceEnd(index, size);
    return new CertificateIdentifier(hashedCertIdentifier, genericCertIdentifier);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (hashedCertIdentifier != null) {
      hashedCertIdentifier.toStringWithLineSep(buf, indentLevel, "hashedCertIdentifier", true);
    }

    if (genericCertIdentifier != null) {
      genericCertIdentifier.toStringWithLineSep(buf, indentLevel, "genericCertIdentifier", true);
    }

    if (hashedCertIdentifier != null || genericCertIdentifier != null) {
      buf.deleteCharAt(buf.length() - 1);
    }
    return buf;
  }
}
