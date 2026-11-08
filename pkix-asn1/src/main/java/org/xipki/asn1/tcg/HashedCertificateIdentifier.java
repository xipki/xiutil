// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * HashedCertificateIdentifier ::= SEQUENCE {
 *     hashAlgorithm AlgorithmIdentifier,
 *     hashOverSignatureValue OCTET STRING
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class HashedCertificateIdentifier extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlgorithm;

  private final Asn1OctetString hashOverSignatureValue;

  public HashedCertificateIdentifier(
      AlgorithmIdentifier hashAlgorithm, byte[] hashOverSignatureValue) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.hashOverSignatureValue = new Asn1OctetString(
        Args.notEmpty(hashOverSignatureValue, "hashOverSignatureValue"));
  }

  public HashedCertificateIdentifier(
      AlgorithmIdentifier hashAlgorithm, Asn1OctetString hashOverSignatureValue) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.hashOverSignatureValue = Args.notNull(hashOverSignatureValue, "hashOverSignatureValue");
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(hashAlgorithm, hashOverSignatureValue);
  }

  public static HashedCertificateIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
      return new HashedCertificateIdentifier(
          AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0)),
          seq.getOctetStringAt(1));
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public Asn1OctetString getHashOverSignatureValue() {
    return hashOverSignatureValue;
  }

  public byte[] hashOverSignatureValue() {
    return hashOverSignatureValue.getOctets();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    return hashOverSignatureValue.toStringWithLineSep(buf, indentLevel, "hashOverSignatureValue");
  }

}
