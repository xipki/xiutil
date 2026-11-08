// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.DerivedBitString;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.ipadress.Rfc3779IPAddress;

/**
 * ASN1 IPAddress.
 * <pre>
 * IPAddress ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1IPAddress extends DerivedBitString {

  public Asn1IPAddress(byte[] bytes, int unusedBits) throws CodecException {
    super(new Asn1BitString(bytes, unusedBits));
  }

  @Override
  protected void checkValue(Asn1BitString value) throws CodecException {
  }

  private Asn1IPAddress(Asn1BitString bitString) throws CodecException {
    super(bitString);
  }

  public static Asn1IPAddress fromAsn1(Asn1BitString bitString) throws CodecException {
    return new Asn1IPAddress(Args.notNull(bitString, "bitString"));
  }

  public String toString(int afi, Rfc3779IPAddress.Context context) {
    return new Rfc3779IPAddress(value.getOctets(), value.getUnusedBits()).toString(afi, context);
  }

}
