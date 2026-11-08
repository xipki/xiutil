// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 * CrlID ::= SEQUENCE {
 *     crlUrl  [0] EXPLICIT IA5String OPTIONAL,
 *     crlNum  [1] EXPLICIT INTEGER OPTIONAL,
 *     crlTime [2] EXPLICIT GeneralizedTime OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CrlID extends Asn1Encodable {

  private final Asn1IA5String crlUrl;
  private final Asn1Integer crlNum;
  private final Asn1GeneralizedTime crlTime;

  public CrlID(Asn1IA5String crlUrl, Asn1Integer crlNum, Asn1GeneralizedTime crlTime) {
    this.crlUrl = crlUrl;
    this.crlNum = crlNum;
    this.crlTime = crlTime;
  }

  public static CrlID fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CrlID fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 3);
    int index = 0;
    Asn1IA5String crlUrl = seq.isNotTaggedAt(index, 0) ? null
        : seq.getIA5StringTaggedAt(index++, true);
    Asn1Integer crlNum = seq.isNotTaggedAt(index, 1) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, true);
    Asn1GeneralizedTime crlTime = seq.isNotTaggedAt(index, 2) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, true);
    Asn1Util.checkSequenceEnd(index, size);
    return new CrlID(crlUrl, crlNum, crlTime);
  }

  public Asn1IA5String getCrlUrl() {
    return crlUrl;
  }

  public Asn1Integer getCrlNum() {
    return crlNum;
  }

  public Asn1GeneralizedTime getCrlTime() {
    return crlTime;
  }

  public String crlUrl() {
    return Asn1Util.fromAsn1(crlUrl);
  }

  public Integer crlNum() {
    return Asn1Util.fromAsn1Int(crlNum);
  }

  public Instant crlTime() {
    return Asn1Util.fromAsn1(crlTime);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        crlUrl == null ? null : Asn1TaggedObject.newExplicit(0, crlUrl),
        crlNum == null ? null : Asn1TaggedObject.newExplicit(1, crlNum),
        crlTime == null ? null : Asn1TaggedObject.newExplicit(2, crlTime));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (crlUrl != null) {
      crlUrl.toStringNoLineSep(buf, indentLevel, "crlUrl", true);
    }

    if (crlNum != null) {
      crlNum.toStringNoLineSep(buf, indentLevel, "crlNum", true);
    }

    if (crlTime != null) {
      crlTime.toStringNoLineSep(buf, indentLevel, "crlTime", true);
    }

    return deleteLastNewLine(buf);
  }

}
