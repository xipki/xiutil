// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * Signature       ::=     SEQUENCE {
 *     signatureAlgorithm      AlgorithmIdentifier,
 *     signature               BIT STRING,
 *     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Signature extends Asn1Encodable {

  private final AlgorithmIdentifier signatureAlgorithm;
  private final Asn1BitString signature;
  private final Certificate.Seq0 certs;

  public Signature(AlgorithmIdentifier signatureAlgorithm, Asn1BitString signature) {
    this(signatureAlgorithm, signature, null);
  }

  public Signature(AlgorithmIdentifier signatureAlgorithm,
                   Asn1BitString signature, Certificate.Seq0 certs) {
    this.signatureAlgorithm = Args.notNull(signatureAlgorithm, "signatureAlgorithm");
    this.signature = Args.notNull(signature, "signature");
    this.certs = certs;
  }

  public static Signature fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1BitString signature = seq.getBitStringAt(1);
    Certificate.Seq0 certs = (size == 2) ? null
        : Certificate.Seq0.fromAsn1(seq.getTaggedAt(2, 0).getExplicitSequenceBase());
    return new Signature(signatureAlgorithm, signature, certs);
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public Asn1BitString getSignature() {
    return signature;
  }

  public Certificate.Seq0 getCerts() {
    return certs;
  }

  public byte[] signature() {
    return signature.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(signatureAlgorithm, signature,
        certs == null ? null : Asn1TaggedObject.newExplicit(0, certs));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    signature.toStringWithLineSep(buf, indentLevel, "signature", true);

    if (certs != null) {
      certs.toStringWithLineSep(buf, indentLevel, "certs", true);
    }

    return deleteLastNewLine(buf);
  }
}
