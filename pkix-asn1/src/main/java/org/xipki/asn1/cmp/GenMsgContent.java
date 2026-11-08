// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>GenMsgContent ::= SEQUENCE OF InfoTypeAndValue</pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GenMsgContent extends InfoTypeAndValue.Seq0 {

  public GenMsgContent(InfoTypeAndValue... entries) {
    super(entries);
  }

  public GenMsgContent(List<InfoTypeAndValue> entries) {
    super(entries);
  }

  private GenMsgContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static GenMsgContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new GenMsgContent(seq);
  }

}
