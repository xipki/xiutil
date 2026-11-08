// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.x500.AttributeTypeAndValue;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.PrimitiveType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * CertReqMsg ::= SEQUENCE {
 *   certReq   CertRequest,
 *   popo      ProofOfPossession  OPTIONAL,
 *             -- content depends upon key type
 *   regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertReqMsg extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<CertReqMsg> {

    public Seq1(CertReqMsg... entries) {
      super(entries);
    }

    public Seq1(List<CertReqMsg> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected CertReqMsg newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return CertReqMsg.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final CertRequest certReq;
  private final ProofOfPossession pop;
  private final AttributeTypeAndValue.Seq1 regInfo;

  public CertReqMsg(CertRequest certReq) {
    this(certReq, null, null);
  }

  public CertReqMsg(CertRequest certReq, ProofOfPossession pop) {
    this(certReq, pop, null);
  }

  public CertReqMsg(CertRequest certReq, ProofOfPossession pop,
                    AttributeTypeAndValue.Seq1 regInfo) {
    this.certReq = Args.notNull(certReq, "certReq");
    this.pop = pop;
    this.regInfo = regInfo;
  }

  public static CertReqMsg fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertReqMsg fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    CertRequest certReq = CertRequest.fromAsn1(seq.getSequenceAt(0));

    int index = 1;
    ProofOfPossession pop = seq.isNotTaggedAt(index) ? null
        : ProofOfPossession.fromAsn1(seq.getTaggedAt(index++));

    AttributeTypeAndValue.Seq1 regInfo = seq.notHasType(index, PrimitiveType.SEQUENCE) ? null
        : AttributeTypeAndValue.Seq1.fromAsn1(seq.getSequenceAt(index++));

    Asn1Util.checkSequenceEnd(index, size);

    return new CertReqMsg(certReq, pop, regInfo);
  }

  public CertRequest getCertReq() {
    return certReq;
  }

  public ProofOfPossession getPop() {
    return pop;
  }

  public AttributeTypeAndValue.Seq1 getRegInfo() {
    return regInfo;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certReq, pop, regInfo);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certReq.toStringWithLineSep(buf, indentLevel, "certReq", true);

    if (pop != null) {
      pop.toStringWithLineSep(buf, indentLevel, "pop", true);
    }

    if (regInfo != null) {
      regInfo.toStringWithLineSep(buf, indentLevel, "regInfo", true);
    }

    return deleteLastNewLine(buf);
  }

}
