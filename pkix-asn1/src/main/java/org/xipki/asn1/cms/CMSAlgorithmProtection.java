// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * From RFC 6211
 * <pre>
 * CMSAlgorithmProtection ::= SEQUENCE {
 *    digestAlgorithm         DigestAlgorithmIdentifier,
 *    signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
 *    macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL
 * }
 * (WITH COMPONENTS { signatureAlgorithm PRESENT,
 *                    macAlgorithm ABSENT } |
 *  WITH COMPONENTS { signatureAlgorithm ABSENT,
 *                    macAlgorithm PRESENT })
 *
 * DigestAlgorithmIdentifier          ::= AlgorithmIdentifier
 * SignatureAlgorithmIdentifier       ::= AlgorithmIdentifier
 * MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CMSAlgorithmProtection extends Asn1Encodable {

  private final AlgorithmIdentifier digestAlgorithm;
  private final AlgorithmIdentifier signatureAlgorithm;
  private final AlgorithmIdentifier macAlgorithm;

  public static CMSAlgorithmProtection fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier digestAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));

    Asn1TaggedObject t = seq.getTaggedAt(1);
    int tagNo = t.getTagNo();

    AlgorithmIdentifier signatureAlgorithm = null;
    AlgorithmIdentifier macAlgorithm = null;

    if (tagNo == 1) {
      signatureAlgorithm = AlgorithmIdentifier.fromAsn1(t.getImplicitSequenceBase());
    } else if (tagNo == 2) {
      macAlgorithm = AlgorithmIdentifier.fromAsn1(t.getImplicitSequenceBase());
    } else {
      throw CodecException.seqWithUnexpectedElements();
    }

    return new CMSAlgorithmProtection(digestAlgorithm, signatureAlgorithm, macAlgorithm);
  }

  private CMSAlgorithmProtection(
      AlgorithmIdentifier digestAlgorithm, AlgorithmIdentifier signatureAlgorithm,
      AlgorithmIdentifier macAlgorithm) {
    this.digestAlgorithm = Args.notNull(digestAlgorithm, "digestAlgorithm");
    if ((signatureAlgorithm == null) == (macAlgorithm == null)) {
      throw new IllegalArgumentException(
          "exactly one of signatureAlgorithm and macAlgorithm shall be null");
    }

    this.signatureAlgorithm = signatureAlgorithm;
    this.macAlgorithm = macAlgorithm;
  }

  public static CMSAlgorithmProtection ofSignatureAlgorithm(
      AlgorithmIdentifier digestAlgorithm, AlgorithmIdentifier signatureAlgorithm) {
    return new CMSAlgorithmProtection(digestAlgorithm, signatureAlgorithm, null);
  }

  public static CMSAlgorithmProtection ofMacAlgorithm(
      AlgorithmIdentifier digestAlgorithm, AlgorithmIdentifier macAlgorithm) {
    return new CMSAlgorithmProtection(digestAlgorithm, null, macAlgorithm);
  }

  public AlgorithmIdentifier getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public AlgorithmIdentifier getMacAlgorithm() {
    return macAlgorithm;
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(digestAlgorithm,
        signatureAlgorithm == null ? null : Asn1TaggedObject.newImplicit(1, signatureAlgorithm),
        macAlgorithm == null ? null : Asn1TaggedObject.newImplicit(2, macAlgorithm));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    digestAlgorithm.toStringWithLineSep(buf, indentLevel, "digestAlgorithm", true);

    if (signatureAlgorithm != null) {
      signatureAlgorithm.toStringWithLineSep(buf, indentLevel, "signatureAlgorithm", true);
    }

    if (macAlgorithm != null) {
      macAlgorithm.toStringWithLineSep(buf, indentLevel, "macAlgorithm", true);
    }

    return deleteLastNewLine(buf);
  }

}
