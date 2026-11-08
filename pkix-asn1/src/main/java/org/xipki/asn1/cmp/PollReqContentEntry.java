// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * <pre>
 * PollReqContent ::= SEQUENCE OF SEQUENCE {
 *     certReqId    INTEGER
 * }
 * </pre>
 *
 * This class represents
 * <pre>
 * SEQUENCE {
 *      certReqId    INTEGER
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PollReqContentEntry extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<PollReqContentEntry> {

    public Seq0(PollReqContentEntry... entries) {
      super(entries);
    }

    public Seq0(List<PollReqContentEntry> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected PollReqContentEntry newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PollReqContentEntry.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Integer certReqId;

  public static PollReqContentEntry fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 1);
    Asn1Integer certReqId = seq.getIntegerAt(0);
    return new PollReqContentEntry(certReqId);
  }

  public PollReqContentEntry(Asn1Integer certReqId) {
    this.certReqId = Args.notNull(certReqId, "certReqId");
  }

  public Asn1Integer getCertReqId() {
    return certReqId;
  }

  public BigInteger certReqId() {
    return certReqId.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(certReqId);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certReqId.toStringNoLineSep(buf, indentLevel, "certReqId", true);

    return deleteLastNewLine(buf);
  }

}
