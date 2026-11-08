// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * ComponentAddresses ::= SEQUENCE(SIZE(1..MAX) OF ComponentAddress
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentAddresses extends ComponentAddress.Seq1 {

  public ComponentAddresses(ComponentAddress... entries) {
    super(entries);
  }

  public ComponentAddresses(List<ComponentAddress> entries) {
    super(entries);
  }

  protected ComponentAddresses(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static ComponentAddresses fromAsn1(Asn1Sequence seq) throws CodecException {
    return new ComponentAddresses(seq);
  }

}
