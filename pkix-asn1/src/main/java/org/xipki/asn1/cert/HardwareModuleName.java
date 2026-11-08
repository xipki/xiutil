// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 *  The hardware module name form is identified by the id-on-
 *  hardwareModuleName object identifier:
 *
 *  RFC 4108:
 *  <pre>
 *     id-on-hardwareModuleName OBJECT IDENTIFIER ::= {
 *       iso(1) identified-organization(3) dod(6) internet(1) security(5)
 *       mechanisms(5) pkix(7) on(8) 4 }
 *  </pre>
 *
 *  A HardwareModuleName is composed of an object identifier and an octet
 *  string:
 *
 *  <pre>
 *  HardwareModuleName ::= SEQUENCE {
 *      hwType       OBJECT IDENTIFIER,
 *      hwSerialNum  OCTET STRING }
 * </pre>
 *
 *  The fields of the HardwareModuleName type have the following
 *  meanings:
 * <ol>
 * <li>hwType is an object identifier that identifies the type of hardware
 *     module.  A unique object identifier names a hardware model and
 *     revision.</li>
 * <li>hwSerialNum is the serial number of the hardware module.  No
 *     particular structure is imposed on the serial number; it need not
 *     be an integer.  However, the combination of the hwType and
 *     hwSerialNum uniquely identifies the hardware module.</li>
 * </ol>
 *
 * @author Lijun Liao (xipki)
 */
public class HardwareModuleName extends Asn1Encodable {

  private final Asn1Oid hwType;

  private final Asn1OctetString hwSerialNum;

  public HardwareModuleName(Asn1Oid hwType, byte[] hwSerialNum) {
    this.hwType = Args.notNull(hwType, "hwType");
    this.hwSerialNum = new Asn1OctetString(Args.notEmptyBytes(hwSerialNum, "hwSerialNum"));
  }

  public HardwareModuleName(Asn1Oid hwType, Asn1OctetString hwSerialNum) {
    this.hwType = Args.notNull(hwType, "hwType");
    this.hwSerialNum = Args.notNull(hwSerialNum, "hwSerialNum");
  }

  public Asn1Oid getHwType() {
    return hwType;
  }

  public Asn1OctetString getHwSerialNum() {
    return hwSerialNum;
  }

  public byte[] hwSerialNum() {
    return hwSerialNum.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(hwType, hwSerialNum);
  }

  public static HardwareModuleName fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid hwType = seq.getOidAt(0);
    Asn1OctetString hwSerialNum = seq.getOctetStringAt(1);
    return new HardwareModuleName(hwType, hwSerialNum);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    hwType.toStringNoLineSep(buf, indentLevel, "hwType", true);
    return hwSerialNum.toStringWithLineSep(buf, indentLevel, "hwSerialNum");
  }

}
