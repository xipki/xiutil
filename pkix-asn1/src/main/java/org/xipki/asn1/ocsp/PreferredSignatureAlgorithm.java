// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.smime.SMIMECapability;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 6960:
 * <pre>
 * PreferredSignatureAlgorithm ::= SEQUENCE {
 *     sigIdentifier        AlgorithmIdentifier,
 *     pubKeyAlgIdentifier  SMIMECapability OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PreferredSignatureAlgorithm extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<PreferredSignatureAlgorithm> {

    public Seq0(PreferredSignatureAlgorithm... entries) {
      super(entries);
    }

    public Seq0(List<PreferredSignatureAlgorithm> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected PreferredSignatureAlgorithm newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PreferredSignatureAlgorithm.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final AlgorithmIdentifier sigIdentifier;

  private final SMIMECapability pubKeyAlgIdentifier;

  public PreferredSignatureAlgorithm(
      AlgorithmIdentifier sigIdentifier, SMIMECapability pubKeyAlgIdentifier) {
    this.sigIdentifier = Args.notNull(sigIdentifier, "sigIdentifier");
    this.pubKeyAlgIdentifier = pubKeyAlgIdentifier;
  }

  public PreferredSignatureAlgorithm(AlgorithmIdentifier sigIdentifier) {
    this(sigIdentifier, null);
  }

  public static PreferredSignatureAlgorithm fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PreferredSignatureAlgorithm fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    AlgorithmIdentifier sigId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    SMIMECapability pubKeyAlgId = (size == 1) ? null
        : SMIMECapability.fromAsn1(seq.getSequenceAt(1));
    return new PreferredSignatureAlgorithm(sigId, pubKeyAlgId);
  }

  public AlgorithmIdentifier getSigIdentifier() {
    return sigIdentifier;
  }

  public SMIMECapability getPubKeyAlgIdentifier() {
    return pubKeyAlgIdentifier;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(sigIdentifier, pubKeyAlgIdentifier);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    sigIdentifier.toStringWithLineSep(buf, indentLevel, "sigIdentifier", true);

    if (pubKeyAlgIdentifier != null) {
      pubKeyAlgIdentifier.toStringWithLineSep(buf, indentLevel, "pubKeyAlgIdentifier", true);
    }

    return deleteLastNewLine(buf);
  }
}
