// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.CRLReason;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Enumerated;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime          GeneralizedTime,
 *     revocationReason    [0] EXPLICIT CRLReason OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevokedInfo extends Asn1Encodable {

  private final Asn1GeneralizedTime revocationTime;
  private final CRLReason revocationReason;

  public RevokedInfo(Asn1GeneralizedTime revocationTime) {
    this(revocationTime, null);
  }

  public RevokedInfo(Asn1GeneralizedTime revocationTime, CRLReason revocationReason) {
    this.revocationTime = Args.notNull(revocationTime, "revocationTime");
    this.revocationReason = revocationReason;
  }

  public static RevokedInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1GeneralizedTime revocationTime = seq.getGeneralizedTimeAt(0);
    if (size == 1) {
      return new RevokedInfo(revocationTime);
    } else {
      Asn1Enumerated enumerated = seq.getTaggedAt(1, 0).getExplicitEnumeratedBase();
      CRLReason revocationReason = CRLReason.getInstance(enumerated.getValue());
      return new RevokedInfo(revocationTime, revocationReason);
    }
  }

  public Asn1GeneralizedTime getRevocationTime() {
    return revocationTime;
  }

  public CRLReason getRevocationReason() {
    return revocationReason;
  }

  public Instant revocationTime() {
    return revocationTime.getTime();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(revocationTime,
        revocationReason == null ? null : Asn1TaggedObject.newExplicit(0, revocationReason));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    revocationTime.toStringNoLineSep(buf, indentLevel, "revocationTime", true);

    if (revocationReason != null) {
      revocationReason.toStringNoLineSep(buf, indentLevel, "revocationReason", true);
    }

    return deleteLastNewLine(buf);
  }

}
