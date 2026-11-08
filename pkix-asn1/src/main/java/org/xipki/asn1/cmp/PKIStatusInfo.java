// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PKIStatusInfo ::= SEQUENCE {
 *      status        PKIStatus,
 *      statusString  PKIFreeText     OPTIONAL,
 *      failInfo      PKIFailureInfo  OPTIONAL
 *  }
 *
 * @author Lijun Liao (xipki)
 */
public class PKIStatusInfo extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<PKIStatusInfo> {

    public Seq1(PKIStatusInfo... entries) {
      super(entries);
    }

    public Seq1(List<PKIStatusInfo> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected PKIStatusInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return PKIStatusInfo.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final PKIStatus status;
  private final PKIFreeText statusString;
  private final PKIFailureInfo failInfo;

  public static PKIStatusInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    Asn1Integer iStatus = seq.getNonNegativeIntegerAt(0);
    PKIStatus status = PKIStatus.getInstance(iStatus.intValueExact());

    int index = 1;
    PKIFreeText statusString = seq.notHasSequence(index) ? null
        : PKIFreeText.fromAsn1(seq.getSequenceAt(index++));

    PKIFailureInfo failureInfo = seq.notHasBitString(index) ? null
        : PKIFailureInfo.fromAsn1(seq.getBitStringAt(index++));

    Asn1Util.checkSequenceEnd(index, size);

    return new PKIStatusInfo(status, statusString, failureInfo);
  }

  public PKIStatusInfo(PKIStatus status) {
    this(status, null, null);
  }

  public PKIStatusInfo(PKIStatus status, PKIFreeText statusString) {
    this(status, statusString, null);
  }

  public PKIStatusInfo(PKIStatus status, PKIFreeText statusString, PKIFailureInfo failInfo) {
    this.status = Args.notNull(status, "status");
    this.statusString = statusString;
    this.failInfo = failInfo;
  }

  public PKIStatus getStatus() {
      return status;
  }

  public PKIFreeText getStatusString() {
      return statusString;
  }

  public PKIFailureInfo getFailInfo() {
      return failInfo;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(status, statusString, failInfo);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    status.toStringNoLineSep(buf, indentLevel, "status", true);

    if (statusString != null) {
      statusString.toStringWithLineSep(buf, indentLevel, "statusString", true);
    }

    if (failInfo != null) {
      failInfo.toStringNoLineSep(buf, indentLevel, "failInfo", true);
    }

    return deleteLastNewLine(buf);
  }

}
