// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * CertResponse ::= SEQUENCE {
 *     certReqId           INTEGER,
 *     status              PKIStatusInfo,
 *     certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
 *     rspInfo             OCTET STRING        OPTIONAL
 *       -- analogous to the id-regInfo-utf8Pairs string defined
 *       -- for regInfo in CertReqMsg [CRMF]
 * }
 *
 * @author Lijun Liao (xipki)
 */
public class CertResponse extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<CertResponse> {

    public Seq0(CertResponse... entries) {
      super(entries);
    }

    public Seq0(List<CertResponse> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromEncoded(byte[] encoded) throws CodecException {
      return fromAsn1(Asn1Sequence.fromEncoded(encoded));
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected CertResponse newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return CertResponse.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Integer certReqId;
  private final PKIStatusInfo status;
  private final CertifiedKeyPair certifiedKeyPair;
  private final Asn1OctetString rspInfo;

  public static CertResponse fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    Asn1Integer certReqId = seq.getIntegerAt(0);
    PKIStatusInfo status = PKIStatusInfo.fromAsn1(seq.getSequenceAt(1));

    int index = 2;
    CertifiedKeyPair certifiedKeyPair = seq.notHasSequence(index) ? null
        : CertifiedKeyPair.fromAsn1(seq.getSequenceAt(index++));

    Asn1OctetString rspInfo = seq.notHasOctetString(index) ? null : seq.getOctetStringAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new CertResponse(certReqId, status, certifiedKeyPair, rspInfo);
  }

  public CertResponse(Asn1Integer certReqId, PKIStatusInfo status) {
    this(certReqId, status, null, null);
  }

  public CertResponse(Asn1Integer certReqId, PKIStatusInfo status,
                      CertifiedKeyPair certifiedKeyPair, Asn1OctetString rspInfo) {
    this.certReqId = Args.notNull(certReqId, "certReqId");
    this.status = Args.notNull(status, "status");
    this.certifiedKeyPair = certifiedKeyPair;
    this.rspInfo = rspInfo;
  }

  public Asn1Integer getCertReqId() {
    return certReqId;
  }

  public PKIStatusInfo getStatus() {
    return status;
  }

  public CertifiedKeyPair getCertifiedKeyPair() {
    return certifiedKeyPair;
  }

  public Asn1OctetString getRspInfo() {
    return rspInfo;
  }

  public BigInteger certReqId() {
    return certReqId.getValue();
  }

  public byte[] rspInfo() {
    return Asn1Util.fromAsn1(rspInfo);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certReqId, status, certifiedKeyPair, rspInfo);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certReqId.toStringNoLineSep(buf, indentLevel, "certReqId", true);
    status.toStringWithLineSep(buf, indentLevel, "status", true);

    if (certifiedKeyPair != null) {
      certifiedKeyPair.toStringWithLineSep(buf, indentLevel, "certifiedKeyPair", true);
    }

    if (rspInfo != null) {
      rspInfo.toStringWithLineSep(buf, indentLevel, "rspInfo", true);
    }

    return deleteLastNewLine(buf);
  }

}
