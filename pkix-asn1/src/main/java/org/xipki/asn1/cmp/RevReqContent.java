// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 *  <pre>
 *  RevReqContent ::= SEQUENCE OF RevDetails
 *  </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevReqContent extends RevDetails.Seq0 {

  public RevReqContent(RevDetails... entries) {
    super(entries);
  }

  public RevReqContent(List<RevDetails> entries) {
    super(entries);
  }

  protected RevReqContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static RevReqContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new RevReqContent(seq);
  }

}
