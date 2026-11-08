// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.DerivedOctetString;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * MACAddress ::= OCTET STRING (SIZE (6 | 8 | 12 | 16))
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class MacAddress extends DerivedOctetString {

  @Override
  protected void checkValue(Asn1OctetString value) throws CodecException {
    int len = value.getOctetsLength();
    if (len == 6 || len == 8 || len == 12 || len == 16) {
      return;
    }
    throw new CodecException("invalid length of value " + len + ": not among [6, 8 12, 16]");
  }

  public MacAddress(Asn1OctetString value) throws CodecException {
    super(value);
  }

  public MacAddress(byte[] value) throws CodecException {
    super(value);
  }

}
