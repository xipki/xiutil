// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * OriginatorPublicKey ::= SEQUENCE {
 *     algorithm  AlgorithmIdentifier,
 *     publicKey  BIT STRING
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OriginatorPublicKey extends Asn1Encodable {

  private final AlgorithmIdentifier algorithm;
  private final Asn1BitString publicKey;

  public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.publicKey = new Asn1BitString(Args.notNull(publicKey, "publicKey"));
  }

  public OriginatorPublicKey(AlgorithmIdentifier algorithm, Asn1BitString publicKey) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.publicKey = Args.notNull(publicKey, "publicKey");
  }

  public static OriginatorPublicKey fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier algorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1BitString publicKey = seq.getBitStringAt(1);
    return new OriginatorPublicKey(algorithm, publicKey);
  }

  public AlgorithmIdentifier getAlgorithm() {
    return algorithm;
  }

  public Asn1BitString getPublicKeyData() {
    return publicKey;
  }

  public byte[] publicKeyData() {
    return publicKey.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(algorithm, publicKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    algorithm.toStringWithLineSep(buf, indentLevel, "algorithm", true);
    publicKey.toStringWithLineSep(buf, indentLevel, "publicKey", true);

    return deleteLastNewLine(buf);
  }

}
