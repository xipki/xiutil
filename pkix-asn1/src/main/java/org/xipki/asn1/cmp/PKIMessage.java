// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 4210:
 * <pre>
 * PKIMessage ::= SEQUENCE {
 *     header           PKIHeader,
 *     body             PKIBody,
 *     protection   [0] PKIProtection OPTIONAL,
 *     extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
 * }
 *
 * PKIProtection ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKIMessage extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<PKIMessage> {

    public Seq1(PKIMessage... entries) {
      super(entries);
    }

    public Seq1(List<PKIMessage> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected PKIMessage newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return PKIMessage.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final PKIHeader header;
  private final PKIBody body;
  private final Asn1BitString protection;
  private final CMPCertificate.Seq1 extraCerts;

  public static PKIMessage fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PKIMessage fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    PKIHeader header = PKIHeader.fromAsn1(seq.getSequenceAt(0));
    PKIBody body = PKIBody.fromAsn1(seq.getTaggedAt(1));

    int index = 2;
    Asn1BitString protection = seq.isNotTaggedAt(index, 0) ? null
        : seq.getBitStringTaggedAt(index++, true);

    CMPCertificate.Seq1 extraCerts = seq.isNotTaggedAt(index, 1) ? null
        : CMPCertificate.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    return new PKIMessage(header, body, protection, extraCerts);
  }

  public PKIMessage(PKIHeader header, PKIBody body,
                    Asn1BitString protection, CMPCertificate.Seq1 extraCerts) {
    this.header = Args.notNull(header, "header");
    this.body = Args.notNull(body, "body");
    this.protection = protection;
    this.extraCerts = extraCerts;
  }

  public PKIMessage(PKIHeader header, PKIBody body, Asn1BitString protection) {
    this(header, body, protection, null);
  }

  public PKIMessage(PKIHeader header, PKIBody body) {
    this(header, body, null, null);
  }

  public PKIHeader getHeader() {
    return header;
  }

  public PKIBody getBody() {
    return body;
  }

  public Asn1BitString getProtection() {
    return protection;
  }

  public boolean hasProtection() {
    return protection != null;
  }

  public byte[] protection() {
    return Asn1Util.fromAsn1(protection);
  }

  public CMPCertificate.Seq1 getExtraCerts() {
    return extraCerts;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(header, body,
        protection == null ? null : Asn1TaggedObject.newExplicit(0, protection),
        extraCerts == null ? null : Asn1TaggedObject.newExplicit(1, extraCerts));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    header.toStringWithLineSep(buf, indentLevel, "header", true);
    body.toStringWithLineSep(buf, indentLevel, "body", true);

    if (protection != null) {
      protection.toStringWithLineSep(buf, indentLevel, "protection", true);
    }

    if (extraCerts != null) {
      extraCerts.toStringWithLineSep(buf, indentLevel, "extraCerts", true);
    }

    return deleteLastNewLine(buf);
  }

}
