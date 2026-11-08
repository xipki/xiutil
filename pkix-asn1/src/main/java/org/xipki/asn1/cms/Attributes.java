// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * Attributes ::= SET SIZE (1..MAX) OF Attribute
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Attributes extends Attribute.Set1 {

  public Attributes(Attribute... entries) {
    super(entries);
  }

  public Attributes(List<Attribute> entries) {
    super(entries);
  }

  protected Attributes(Asn1Set set) throws CodecException {
    super(set);
  }

  public static Attributes fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Set.fromEncoded(encoded));
  }

  public static Attributes fromAsn1(Asn1Set set) throws CodecException {
    return new Attributes(set);
  }

}
