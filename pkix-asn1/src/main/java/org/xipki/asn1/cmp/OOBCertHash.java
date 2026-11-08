// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertId;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * OOBCertHash ::= SEQUENCE {
 *     hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
 *     certId      [1] CertId                  OPTIONAL,
 *     hashVal         BIT STRING
 *     -- hashVal is calculated over the DER encoding of the
 *     -- self-signed certificate with the identifier certID.
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OOBCertHash extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlg;
  private final CertId certId;
  private final Asn1BitString hashVal;

  public static OOBCertHash fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    int index = 0;
    AlgorithmIdentifier hashAlg = seq.isNotTaggedAt(index, 0) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getTaggedAt(index++).getExplicitSequenceBase());

    CertId certId = seq.isNotTaggedAt(index, 1) ? null
        : CertId.fromAsn1(seq.getTaggedAt(index++).getExplicitSequenceBase());

    Asn1BitString hashVal = seq.getBitStringAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new OOBCertHash(hashAlg, certId, hashVal);
  }

  public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal) {
    this(hashAlg, certId, new Asn1BitString(Args.notNull(hashVal, "hashVal")));
  }

  public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, Asn1BitString hashVal) {
    this.hashAlg = hashAlg;
    this.certId = certId;
    this.hashVal = Args.notNull(hashVal, "hashVal");
  }

  public AlgorithmIdentifier getHashAlg() {
    return hashAlg;
  }

  public CertId getCertId() {
    return certId;
  }

  public Asn1BitString getHashVal() {
    return hashVal;
  }

  public byte[] hashVal() {
    return hashVal.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        hashAlg == null ? null : Asn1TaggedObject.newExplicit(0, hashAlg),
        certId == null  ? null : Asn1TaggedObject.newExplicit(1, certId),
        hashVal);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (hashAlg != null) {
      hashAlg.toStringWithLineSep(buf, indentLevel, "hashAlg", true);
    }

    if (certId != null) {
      certId.toStringWithLineSep(buf, indentLevel, "certId", true);
    }

    hashVal.toStringWithLineSep(buf, indentLevel, "hashVal", true);

    return deleteLastNewLine(buf);
  }
}
