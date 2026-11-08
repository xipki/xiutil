// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * IPAddress Choice.
 *
 * <pre>
 *    IPAddressChoice     ::= CHOICE {
 *       inherit              NULL, -- inherit from issuer --
 *       addressesOrRanges    SEQUENCE OF IPAddressOrRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressChoice extends Asn1Encodable {

  private static final IPAddressChoice INHERIT = new IPAddressChoice(null);

  private final IPAddressOrRange.Seq0 addressesOrRanges;

  private IPAddressChoice(IPAddressOrRange.Seq0 addressesOrRanges) {
    this.addressesOrRanges = addressesOrRanges;
  }

  public static IPAddressChoice ofInherit() {
    return INHERIT;
  }

  public static IPAddressChoice ofAddressesOrRanges(IPAddressOrRange.Seq0 addressesOrRanges) {
    return new IPAddressChoice(Args.notNull(addressesOrRanges, "addressesOrRanges"));
  }

  public static IPAddressChoice fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    if (asn1 instanceof Asn1Null) {
      return new IPAddressChoice(null);
    } else if (asn1 instanceof Asn1Sequence) {
      return new IPAddressChoice(IPAddressOrRange.Seq0.fromAsn1((Asn1Sequence) asn1));
    } else {
      throw new CodecException("invalid ASN1 type " + asn1.getClass().getName());
    }
  }

  public boolean isInherit() {
    return addressesOrRanges == null;
  }

  public IPAddressOrRange.Seq0 getAddressesOrRanges() {
    return addressesOrRanges;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return (addressesOrRanges == null) ? Asn1Null.INSTANCE : addressesOrRanges.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (isInherit()) {
      return ToStringUtil.appendIndent(buf, indentLevel, "inherit");
    } else {
      return addressesOrRanges.toStringWithLineSep(buf, indentLevel, "addressesOrRanges");
    }
  }

}
