// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;
import org.xipki.codec.ipadress.Rfc3779IPAddress;

import java.util.List;

/**
 * IPAddress Or Range.
 * <pre>
 * IPAddressOrRange    ::= CHOICE {
 *     addressPrefix        IPAddress,
 *     addressRange         IPAddressRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressOrRange extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<IPAddressOrRange> {

    public Seq0(IPAddressOrRange... entries) {
      super(entries);
    }

    public Seq0(List<IPAddressOrRange> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected IPAddressOrRange newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return IPAddressOrRange.fromAsn1(coll.getObjectAt(index));
    }
  }

  private final Asn1IPAddress addressPrefix;

  private final IPAddressRange addressRange;

  private IPAddressOrRange(Asn1IPAddress addressPrefix, IPAddressRange addressRange) {
    this.addressPrefix = addressPrefix;
    this.addressRange = addressRange;
  }

  public static IPAddressOrRange ofAddressPrefix(Asn1IPAddress addressPrefix) {
    return new IPAddressOrRange(Args.notNull(addressPrefix, "addressPrefix"), null);
  }

  public static IPAddressOrRange ofAddressRange(IPAddressRange addressRange) {
    return new IPAddressOrRange(null, Args.notNull(addressRange, "addressRange"));
  }

  public static IPAddressOrRange fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    if (asn1 instanceof Asn1Sequence) {
      return ofAddressRange(IPAddressRange.fromAsn1((Asn1Sequence) asn1));
    } else if (asn1 instanceof Asn1BitString) {
      return ofAddressPrefix(Asn1IPAddress.fromAsn1((Asn1BitString) asn1));
    } else {
      throw new CodecException("invalid ASN.1 type " + asn1.type());
    }
  }

  public Asn1IPAddress getAddressPrefix() {
    return addressPrefix;
  }

  public IPAddressRange getAddressRange() {
    return addressRange;
  }

  public String toString(int afi) {
    return (addressPrefix != null)
        ? addressPrefix.toString(afi, Rfc3779IPAddress.Context.PREFIX)
        : addressRange.toString(afi);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return addressPrefix != null
        ? addressPrefix.toAsn1Primitive()
        : addressRange.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return addressPrefix != null
        ? addressPrefix.toStringWithLineSep(buf, indentLevel, "addressPrefix")
        : addressRange.toStringWithLineSep(buf, indentLevel, "addressRange");
  }

  public StringBuilder toString(StringBuilder buf, int indentLevel, int afi) {
    return ToStringUtil.appendIndent(buf, indentLevel, toString(afi));
  }

}
