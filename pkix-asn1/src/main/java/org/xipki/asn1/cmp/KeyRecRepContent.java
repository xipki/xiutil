// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * KeyRecRepContent ::= SEQUENCE {
 *     status           PKIStatusInfo,
 *     newSigCert   [0] CMPCertificate OPTIONAL,
 *     caCerts      [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
 *     keyPairHist  [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KeyRecRepContent extends Asn1Encodable {

  private final PKIStatusInfo status;
  private final CMPCertificate newSigCert;
  private final CMPCertificate.Seq1 caCerts;
  private final CertifiedKeyPair.Seq1 keyPairHist;

  public KeyRecRepContent(PKIStatusInfo status, CMPCertificate newSigCert,
                          CMPCertificate.Seq1 caCerts, CertifiedKeyPair.Seq1 keyPairHist) {
    this.status = Args.notNull(status, "status");
    this.newSigCert = newSigCert;
    this.caCerts = caCerts;
    this.keyPairHist = keyPairHist;
  }

  public static KeyRecRepContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 4);
    PKIStatusInfo status = PKIStatusInfo.fromAsn1(seq.getSequenceAt(0));
    int index = 1;
    CMPCertificate newSigCert = seq.isNotTaggedAt(index, 0) ? null
        : CMPCertificate.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    CMPCertificate.Seq1 caCerts = seq.isNotTaggedAt(index, 1) ? null
        : CMPCertificate.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    CertifiedKeyPair.Seq1 keyPairHist = seq.isNotTaggedAt(index, 2) ? null
        : CertifiedKeyPair.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    return new KeyRecRepContent(status, newSigCert, caCerts, keyPairHist);
  }

  public PKIStatusInfo getStatus() {
    return status;
  }

  public CMPCertificate getNewSigCert() {
    return newSigCert;
  }

  public CMPCertificate.Seq1 getCaCerts() {
    return caCerts;
  }

  public CertifiedKeyPair.Seq1 getKeyPairHist() {
    return keyPairHist;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(status,
        newSigCert == null ? null : Asn1TaggedObject.newExplicit(0, newSigCert),
        caCerts == null ? null : Asn1TaggedObject.newExplicit(1, caCerts),
        keyPairHist == null ? null : Asn1TaggedObject.newExplicit(2, keyPairHist));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    status.toStringWithLineSep(buf, indentLevel, "status", true);

    if (newSigCert != null) {
      newSigCert.toStringWithLineSep(buf, indentLevel, "newSigCert", true);
    }

    if (caCerts != null) {
      caCerts.toStringWithLineSep(buf, indentLevel, "caCerts", true);
    }

    if (keyPairHist != null) {
      keyPairHist.toStringWithLineSep(buf, indentLevel, "keyPairHist", true);
    }

    return deleteLastNewLine(buf);
  }

}
