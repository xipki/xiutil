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
 * PollRepContent ::= SEQUENCE OF SEQUENCE {
 *   certReqId    INTEGER,
 *   checkAfter   INTEGER,  -- time in seconds
 *   reason       PKIFreeText OPTIONAL
 * }
 *
 * @author Lijun Liao (xipki)
 */
public class PollRepContentEntry extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<PollRepContentEntry> {

    public Seq0(PollRepContentEntry... entries) {
      super(entries);
    }

    public Seq0(List<PollRepContentEntry> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected PollRepContentEntry newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PollRepContentEntry.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Integer certReqId;
  private final Asn1Integer checkAfter;
  private final PKIFreeText reason;

  public static PollRepContentEntry fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer certReqId = seq.getIntegerAt(0);
    Asn1Integer checkAfter = seq.getNonNegativeIntegerAt(1);
    PKIFreeText reason = (size > 2) ? PKIFreeText.fromAsn1(seq.getSequenceAt(2)) :null;
    return new PollRepContentEntry(certReqId, checkAfter, reason);
  }

  public PollRepContentEntry(Asn1Integer certReqId, Asn1Integer checkAfter) {
    this(certReqId, checkAfter, null);
  }

  public PollRepContentEntry(Asn1Integer certReqId, Asn1Integer checkAfter, PKIFreeText reason) {
    this.certReqId = Args.notNull(certReqId, "certReqId");
    this.checkAfter = Args.notNull(checkAfter, "checkAfter");
    this.reason = reason;
  }

  public Asn1Integer getCertReqId() {
    return certReqId;
  }

  public Asn1Integer getCheckAfter() {
    return checkAfter;
  }

  public PKIFreeText getReason() {
    return reason;
  }

  public BigInteger certReqId() {
    return certReqId.getValue();
  }

  public long checkAfter() {
    return checkAfter.longValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certReqId, checkAfter, reason);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certReqId.toStringNoLineSep(buf, indentLevel, "certReqId", true);
    checkAfter.toStringNoLineSep(buf, indentLevel, "checkAfter", true);

    if (reason != null) {
      reason.toStringWithLineSep(buf, indentLevel, "reason", true);
    }

    return deleteLastNewLine(buf);
  }

}
