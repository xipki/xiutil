// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.x500.AttributeTypeAndValue;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class Controls extends AttributeTypeAndValue.Seq1 {

  public Controls(AttributeTypeAndValue... entries) {
    super(entries);
  }

  public Controls(List<AttributeTypeAndValue> entries) {
    super(entries);
  }

  protected Controls(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static Controls fromAsn1(Asn1Sequence seq) throws CodecException {
    return new Controls(seq);
  }

}
