// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;
import org.xipki.codec.ipadress.IPAddressFamily;

import java.util.List;

/**
 * ASN1 IPAddress Family.
 * <pre>
 *    IPAddressFamily     ::= SEQUENCE {    -- AFI and optional SAFI --
 *       addressFamily        OCTET STRING (SIZE (2..3)),
 *       ipAddressChoice      IPAddressChoice }
 * </pre>
 *
 * A list of AFI is available under
 * https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
 * <p>
 * A list of SAFI is available under
 * https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1IPAddressFamily extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<Asn1IPAddressFamily> {

    public Seq0(Asn1IPAddressFamily... entries) {
      super(entries);
    }

    public Seq0(List<Asn1IPAddressFamily> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected Asn1IPAddressFamily newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return Asn1IPAddressFamily.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1OctetString addressFamily;

  private final IPAddressChoice ipAddressChoice;

  public Asn1IPAddressFamily(Asn1OctetString addressFamily, IPAddressChoice ipAddressChoice) {
    this.addressFamily = Args.notNull(addressFamily, "addressFamily");
    this.ipAddressChoice = Args.notNull(ipAddressChoice, "ipAddressChoice");
  }

  public Asn1IPAddressFamily(IPAddressFamily addressFamily, IPAddressChoice ipAddressChoice) {
    Args.notNull(addressFamily, "addressFamily");

    int afi = addressFamily.afi();
    Byte safi = addressFamily.safi();
    byte[] bytes = new byte[safi == null ? 2 : 3];
    bytes[0] = (byte) (afi >> 8);
    bytes[1] = (byte) (afi);
    if (safi != null) {
      bytes[2] = safi;
    }
    this.addressFamily = new Asn1OctetString(bytes);
    this.ipAddressChoice = Args.notNull(ipAddressChoice, "ipAddressChoice");
  }

  public static Asn1IPAddressFamily fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);

    Asn1OctetString  addressFamily = seq.getOctetStringAt(0);
    IPAddressChoice ipAddressChoice = IPAddressChoice.fromAsn1(seq.getObjectAt(1));
    return new Asn1IPAddressFamily(addressFamily, ipAddressChoice);
  }

  public Asn1OctetString getAddressFamily() {
    return addressFamily;
  }

  public byte[] addressFamily() {
    return addressFamily.getOctets();
  }

  public int afi() {
    byte[] bytes = addressFamily.getOctets();
    return new IPAddressFamily(bytes).afi();
  }

  public IPAddressChoice ipAddressChoice() {
    return ipAddressChoice;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(addressFamily, ipAddressChoice);
  }

  public String addressFamilyToString() {
    return new IPAddressFamily(addressFamily.getOctets()).toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, addressFamilyToString()).append(":\n");
    return ipAddressChoice.toString(buf, indentLevel + 1);
  }

}
