// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PollReqContent ::= SEQUENCE OF SEQUENCE {
 *     certReqId    INTEGER }
 *
 * @author Lijun Liao (xipki)
 */
public class PollReqContent extends PollReqContentEntry.Seq0 {

  public PollReqContent(PollReqContentEntry... entries) {
    super(entries);
  }

  public PollReqContent(List<PollReqContentEntry> entries) {
    super(entries);
  }

  private PollReqContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PollReqContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PollReqContent(seq);
  }

}
