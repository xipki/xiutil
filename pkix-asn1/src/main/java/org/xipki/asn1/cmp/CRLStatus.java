// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * CRLStatus ::= SEQUENCE {
 * source       CRLSource,
 * thisUpdate   Time OPTIONAL }
 *
 * @author Lijun Liao (xipki)
 */
public class CRLStatus extends Asn1Encodable {

  private final CRLSource source;
  private final Time thisUpdate;

  public static CRLStatus fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    CRLSource source = CRLSource.fromAsn1(seq.getTaggedAt(0));
    Time thisUpdate = (size == 1) ? null : Time.fromAsn1(seq.getTimeAt(1));
    return new CRLStatus(source, thisUpdate);
  }

  public CRLStatus(CRLSource source) {
    this(source, null);
  }

  public CRLStatus(CRLSource source, Time thisUpdate) {
    this.source = Args.notNull(source, "source");
    this.thisUpdate = thisUpdate;
  }

  public CRLSource getSource() {
    return source;
  }

  public Time getThisUpdate() {
    return thisUpdate;
  }

  public Instant thisUpdate() {
    return Asn1Util.fromAsn1(thisUpdate);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(source, thisUpdate);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    source.toStringWithLineSep(buf, indentLevel, "source", true);

    if (thisUpdate != null) {
      thisUpdate.toStringNoLineSep(buf, indentLevel, "thisUpdate", true);
    }

    return deleteLastNewLine(buf);
  }
}
