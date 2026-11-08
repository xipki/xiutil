// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
 *
 * @author Lijun Liao (xipki)
 */
public class PKIMessages extends PKIMessage.Seq1 {

  public PKIMessages(PKIMessage... entries) {
    super(entries);
  }

  public PKIMessages(List<PKIMessage> entries) {
    super(entries);
  }

  protected PKIMessages(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PKIMessages fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PKIMessages(seq);
  }

}
