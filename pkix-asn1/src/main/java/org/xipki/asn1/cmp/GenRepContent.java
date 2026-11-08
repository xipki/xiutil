// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class GenRepContent extends InfoTypeAndValue.Seq0 {

  public GenRepContent(InfoTypeAndValue... entries) {
    super(entries);
  }

  public GenRepContent(List<InfoTypeAndValue> entries) {
    super(entries);
  }

  private GenRepContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static GenRepContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new GenRepContent(seq);
  }

}
