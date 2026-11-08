// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

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
public class PollRepContent extends PollRepContentEntry.Seq0 {

  public PollRepContent(PollRepContentEntry... entries) {
    super(entries);
  }

  public PollRepContent(List<PollRepContentEntry> entries) {
    super(entries);
  }

  private PollRepContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PollRepContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PollRepContent(seq);
  }

}
