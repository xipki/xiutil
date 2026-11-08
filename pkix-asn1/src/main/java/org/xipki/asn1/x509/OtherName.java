// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.cert.HardwareModuleName;
import org.xipki.asn1.cert.MacAddress;
import org.xipki.asn1.cert.SmtpUtf8Mailbox;
import org.xipki.asn1.spdm.DmtfDeviceInfo;
import org.xipki.asn1.tcg.Traits;
import org.xipki.codec.asn1.AbstractCollection;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * The OtherName object.
 * <pre>
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OtherName extends Asn1Encodable {

  private final Asn1Oid typeID;
  private final Asn1Primitive value;

  private boolean parsed;

  private SmtpUtf8Mailbox smtpUTF8Mailbox;

  // MACAddress ::= OCTET STRING (SIZE (6 | 8 | 12 | 16))
  private MacAddress macAddress;

  private HardwareModuleName hardwareModuleName;

  private DmtfDeviceInfo dmtfDeviceInfo;

  private Traits tcgPlatformIdentifier;

  // Microsoft's object security identifier
  private Asn1OctetString microsoftObjectSid;

  private OtherName(Asn1Oid typeID, Asn1Primitive value) {
    this.typeID = Args.notNull(typeID, "typeID");
    this.value  = Args.notNull(value, "value");
  }

  public static OtherName createNoParse(Asn1Oid typeID, Asn1Encodable value) {
    return new OtherName(typeID, value.toAsn1Primitive());
  }

  public static OtherName create(Asn1Oid typeID, Asn1Encodable value) throws CodecException {
    OtherName r = createNoParse(typeID, value);
    r.parseValue();
    return r;
  }

  private static OtherName create2(Asn1Oid typeID, Asn1Encodable value) {
    OtherName r = createNoParse(typeID, value);
    r.parsed = true;
    return r;
  }

  public static OtherName fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "sequence", 2);
    Asn1Oid typeID = seq.getOidAt(0);
    Asn1Primitive value = seq.getTaggedAt(1, 0).getExplicitBase();
    OtherName r = new OtherName(typeID, value);
    r.parseValue();
    return r;
  }

  public static OtherName ofHardwareModuleName(HardwareModuleName value) {
    Args.notNull(value, "value");
    OtherName on = create2(X509OIDs.id_on_hardwareModuleName, value);
    on.hardwareModuleName = value;
    return on;
  }

  public static OtherName ofMacAddress(MacAddress value) {
    Args.notNull(value, "value");
    OtherName on = create2(X509OIDs.id_on_MACAddress, value);
    on.macAddress = value;
    return on;
  }

  public static OtherName ofMacAddress(byte[] value) throws CodecException {
    MacAddress macAddress = new MacAddress(Args.notNull(value, "value"));
    return ofMacAddress(macAddress);
  }

  public static OtherName ofSmtpUTF8Mailbox(SmtpUtf8Mailbox value) {
    Args.notNull(value, "value");
    OtherName on = create2(X509OIDs.id_on_SmtpUTF8Mailbox, value);
    on.smtpUTF8Mailbox = value;
    return on;
  }

  public static OtherName ofSmtpUTF8Mailbox(String value) throws CodecException {
    return ofSmtpUTF8Mailbox(new SmtpUtf8Mailbox(value));
  }

  public static OtherName ofDmtfDeviceInfo(DmtfDeviceInfo value) {
    Args.notNull(value, "value");
    OtherName on = create2(SpdmOIDs.id_DMTF_device_info, value);
    on.dmtfDeviceInfo = value;
    return on;
  }

  public static OtherName ofTcgPlatformIdentifier(Traits value) {
    Args.notNull(value, "value");
    OtherName on = create2(TcgOIDs.tcg_at_platformIdentifier, value);
    on.tcgPlatformIdentifier = value;
    return on;
  }

  public static OtherName ofMicrosoftObjectSid(Asn1OctetString value) {
    Args.notNull(value, "value");
    OtherName on = create2(ExtensionOIDs.id_microsoft_objectSid, value);
    on.microsoftObjectSid = value;
    return on;
  }

  public static OtherName ofMicrosoftObjectSid(byte[] value) {
    return ofMicrosoftObjectSid(Asn1Util.toOctetString(value));
  }

  public Asn1Oid getTypeID()
  {
      return typeID;
  }

  public Asn1Primitive getValue()
  {
      return value;
  }

  public SmtpUtf8Mailbox getSmtpUTF8Mailbox() {
    return smtpUTF8Mailbox;
  }

  public MacAddress getMacAddress() {
    return macAddress;
  }

  public HardwareModuleName getHardwareModuleName() {
    return hardwareModuleName;
  }

  public DmtfDeviceInfo getDmtfDeviceInfo() {
    return dmtfDeviceInfo;
  }

  public Traits getTcgPlatformIdentifier() {
    return tcgPlatformIdentifier;
  }

  public Asn1OctetString getMicrosoftObjectSid() {
    return microsoftObjectSid;
  }

  public byte[] microsoftObjectSid() {
    return Asn1Util.fromAsn1(microsoftObjectSid);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(typeID, new Asn1TaggedObject(true, 0, value));
  }

  public void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    String id = typeID.getId();
    if (id.equals(X509OIDs.id_on_hardwareModuleName.getId())) {
      hardwareModuleName = HardwareModuleName.fromAsn1(value.asSequence());
    } else if (id.equals(X509OIDs.id_on_MACAddress.getId())) {
      macAddress = new MacAddress(value.asOctetString());
    } else if (id.equals(X509OIDs.id_on_SmtpUTF8Mailbox.getId())) {
      smtpUTF8Mailbox = new SmtpUtf8Mailbox(value.asUtf8String());
    } else if (id.equals(SpdmOIDs.id_DMTF_device_info.getId())) {
      dmtfDeviceInfo = new DmtfDeviceInfo(value.asUtf8String());
    } else if (id.equals(TcgOIDs.tcg_at_platformIdentifier.getId())) {
      tcgPlatformIdentifier = Traits.fromAsn1(value.asSequence());
    } else if (id.equals(ExtensionOIDs.id_microsoft_objectSid.getId())) {
      microsoftObjectSid = value.asOctetString();
    }

    parsed = true;
  }

  private Asn1Encodable parsedValue() {
    if (!parsed) {
      return this.value;
    } else if (macAddress != null) {
      return macAddress;
    } else if (hardwareModuleName != null) {
      return hardwareModuleName;
    } else if (smtpUTF8Mailbox != null) {
      return smtpUTF8Mailbox;
    } else if (dmtfDeviceInfo != null) {
      return dmtfDeviceInfo;
    } else if (tcgPlatformIdentifier != null) {
      return tcgPlatformIdentifier;
    } else if (microsoftObjectSid != null) {
      return microsoftObjectSid;
    } else {
      return value;
    }
  }

  @Override
  public int hashCode() {
    return typeID.hashCode() ^ value.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof OtherName)) {
      return false;
    }

    OtherName b = (OtherName) obj;
    return typeID.equals(b.typeID) && value.equals(b.value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    typeID.toStringNoLineSep(buf, indentLevel, "typeID", true);
    Asn1Encodable m = parsedValue();
    if (m instanceof AbstractCollection) {
      return ((AbstractCollection<?>) m).toString(buf, indentLevel, false);
    } else {
      return m.toString(buf, indentLevel + 1);
    }
  }

}
