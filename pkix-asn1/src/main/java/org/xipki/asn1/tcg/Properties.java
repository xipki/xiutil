// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * Properties ::= SEQUENCE(SIZE(1..MAX) OF Property
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Properties extends Property.Seq1 {

  public Properties(Property... entries) {
    super(entries);
  }

  public Properties(List<Property> entries) {
    super(entries);
  }

  protected Properties(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static Properties fromAsn1(Asn1Sequence seq) throws CodecException {
    return new Properties(seq);
  }

}
