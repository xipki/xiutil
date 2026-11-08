// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.IntegerSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * POPODecKeyRespContent ::= SEQUENCE OF INTEGER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class POPODecKeyRespContent extends IntegerSeq {

  public POPODecKeyRespContent(Asn1Integer... entries) {
    super(0, entries);
  }

  public POPODecKeyRespContent(List<Asn1Integer> entries) {
    super(0, entries);
  }

  protected POPODecKeyRespContent(Asn1Sequence seq) throws CodecException {
    super(0, seq);
  }

  public static POPODecKeyRespContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new POPODecKeyRespContent(seq);
  }

}
