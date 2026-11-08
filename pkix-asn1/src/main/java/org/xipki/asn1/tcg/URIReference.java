// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * -- Reference to external document containing information relevant to this subject.
 * -- The hashAlgorithm and hashValue MUST both exist in each reference if either
 * -- is present.
 * URIReference ::= SEQUENCE {
 *     uniformResourceIdentifier  IA5String (SIZE (1..URIMAX)),
 *     hashAlgorithm              AlgorithmIdentifier OPTIONAL,
 *     hashValue                  BIT STRING OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class URIReference extends Asn1Encodable {

  private final Asn1IA5String uri;

  private final AlgorithmIdentifier hashAlgorithm;

  private final Asn1BitString hashValue;

  public URIReference(String uri, AlgorithmIdentifier hashAlgorithm, byte[] hashValue) {
    this(Asn1Util.toIA5String(uri), hashAlgorithm, Asn1Util.toBitString(hashValue));
  }

  public URIReference(Asn1IA5String uri, AlgorithmIdentifier hashAlgorithm,
                      Asn1BitString hashValue) {
    this.uri = Args.notNull(uri, "uri");
    Args.lengthRange(uri.getString(), "uri", 1, TcgConstants.STRMAX);
    if (hashAlgorithm == null && hashValue != null) {
      throw new IllegalArgumentException("hashAlgorithm is null but hashValue is not present");
    }
    if (hashAlgorithm != null && hashValue == null) {
      throw new IllegalArgumentException("hashAlgorithm is present but hashValue is null");
    }
    this.hashAlgorithm = hashAlgorithm;
    this.hashValue = hashValue;
  }

  public Asn1IA5String getUri() {
    return uri;
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public Asn1BitString getHashValue() {
    return hashValue;
  }

  public String uri() {
    return uri.getString();
  }

  public byte[] hashValue() {
    return Asn1Util.fromAsn1(hashValue);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(uri, hashAlgorithm,
        hashAlgorithm == null ? null : hashValue);
  }

  public static URIReference fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static URIReference fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.notNull(seq, "seq").size();
    if (size != 1 && size != 3) {
      throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
    }

    Asn1IA5String uri = seq.getIA5StringAt(0);
    AlgorithmIdentifier hashAlg = null;
    Asn1BitString hashValue = null;
    if (size == 3) {
      hashAlg = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
      hashValue = seq.getBitStringAt(2);
    }

    return new URIReference(uri, hashAlg, hashValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    uri.toStringNoLineSep(buf, indentLevel, "uri", true);
    if (hashAlgorithm != null) {
      hashAlgorithm.toStringNoLineSep(buf, indentLevel, "hashAlgorithm", true);
    }
    if (hashValue != null) {
      hashValue.toStringNoLineSep(buf, indentLevel, "hashValue", true);
    }

    return deleteLastNewLine(buf);
  }

}
