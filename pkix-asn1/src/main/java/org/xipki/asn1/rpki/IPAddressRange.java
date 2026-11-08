// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.ipadress.Rfc3779IPAddress;

/**
 * IPAddress Range.
 * <pre>
 * IPAddressRange      ::= SEQUENCE {
 *     min                  IPAddress,
 *     max                  IPAddress }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressRange extends Asn1Encodable {

  private final Asn1IPAddress min;

  private final Asn1IPAddress max;

  public IPAddressRange(Asn1IPAddress min, Asn1IPAddress max) {
    this.min = Args.notNull(min, "min");
    this.max = Args.notNull(max, "max");
  }

  public static IPAddressRange fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);

    Asn1IPAddress min = Asn1IPAddress.fromAsn1(seq.getBitStringAt(0));
    Asn1IPAddress max = Asn1IPAddress.fromAsn1(seq.getBitStringAt(1));
    return new IPAddressRange(min, max);
  }

  public Asn1IPAddress getMin() {
    return min;
  }

  public Asn1IPAddress getMax() {
    return max;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(min, max);
  }

  public String toString(int afi) {
    return min.toString(afi, Rfc3779IPAddress.Context.RANGE_MIN) + " - "
        + max.toString(afi, Rfc3779IPAddress.Context.RANGE_MAX);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    min.toStringNoLineSep(buf, indentLevel, "min", true);
    return max.toStringNoLineSep(buf, indentLevel, "max");
  }

}
