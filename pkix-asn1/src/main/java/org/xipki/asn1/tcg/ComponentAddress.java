// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * ComponentAddress ::= SEQUENCE {
 *     addressType  AddressType,
 *     addressValue UTF8String (SIZE (1..STRMAX))
 * }
 * AddressType ::= OBJECT IDENTIFIER ( tcg-address-ethernetmac | tcg-address-wlanmac
 *                 | tcg-address-bluetoothmac )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentAddress extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<ComponentAddress> {

    public Seq1(ComponentAddress... entries) {
      super(entries);
    }

    public Seq1(List<ComponentAddress> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected ComponentAddress newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return ComponentAddress.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid addressType;

  private final Asn1Utf8String addressValue;

  public ComponentAddress(Asn1Oid addressType, String addressValue) {
    this(addressType, Asn1Util.toUtf8String(addressValue));
  }

  public ComponentAddress(Asn1Oid addressType, Asn1Utf8String addressValue) {
    this.addressType = Args.notNull(addressType, "addressType");
    this.addressValue = Args.notNull(addressValue, "addressValue");
    Args.lengthRange(addressValue.getString(), "addressValue", 1, TcgConstants.STRMAX);

    if (!(TcgOIDs.tcg_address_ethernetmac.equals(addressType) ||
        TcgOIDs.tcg_address_wlanmac.equals(addressType) ||
        TcgOIDs.tcg_address_bluetoothmac.equals(addressType))) {
      throw new IllegalArgumentException("invalid addressType " + addressType.getId());
    }
  }

  public Asn1Oid getAddressType() {
    return addressType;
  }

  public Asn1Utf8String getAddressValue() {
    return addressValue;
  }

  public String addressValue() {
    return addressValue.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(addressType, addressValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    addressType.toStringNoLineSep(buf, indentLevel, "addressType", true);
    addressValue.toStringNoLineSep(buf, indentLevel, "addressValue", true);

    return deleteLastNewLine(buf);
  }

  public static ComponentAddress fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ComponentAddress fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new ComponentAddress(seq.getOidAt(0), seq.getUtf8StringAt(1));
  }

}
