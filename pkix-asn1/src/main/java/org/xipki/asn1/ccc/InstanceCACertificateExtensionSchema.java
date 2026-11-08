// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.ccc;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * CCC InstanceCACertificateExtensionSchema.
 * <pre>
 * InstanceCACertificateExtensionSchema ::= SEQUENCE {
 *     extension_version    INTEGER (1..255),
 *     applet_version       OCTET STRING (SIZE (4)),
 *     platform_information OCTET STRING (SIZE (1..20)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class InstanceCACertificateExtensionSchema extends Asn1Encodable {

  private final Asn1Integer extensionVersion;
  private final Asn1OctetString appletVersion;
  private final Asn1OctetString platformInformation;

  public InstanceCACertificateExtensionSchema(
      int extensionVersion, byte[] appletVersion, byte[] platformInformation) {
    Args.range(extensionVersion, "extensionVersion", 1, 255);
    this.extensionVersion = new Asn1Integer(BigInteger.valueOf(extensionVersion));
    Args.fixedLen(appletVersion, "appletVersion", 4);
    this.appletVersion = new Asn1OctetString(appletVersion);

    if (platformInformation == null) {
      this.platformInformation = null;
    } else {
      Args.variableLen(platformInformation, "platformInformation", 1, 20);
      this.platformInformation = new Asn1OctetString(platformInformation);
    }
  }

  private InstanceCACertificateExtensionSchema(
      Asn1Integer extensionVersion, Asn1OctetString appletVersion,
      Asn1OctetString platformInformation) {
    this.extensionVersion = Args.range(extensionVersion, "extensionVersion", 1, 255);
    this.appletVersion = Args.fixedLen(appletVersion, "appletVersion", 4);
    if (platformInformation == null) {
      this.platformInformation = null;
    } else {
      this.platformInformation = Args.variableLen(platformInformation,
          "platformInformation", 1, 20);
    }
  }

  public Asn1Integer getExtensionVersion() {
    return extensionVersion;
  }

  public Asn1OctetString getAppletVersion() {
    return appletVersion;
  }

  public Asn1OctetString getPlatformInformation() {
    return platformInformation;
  }

  public int extensionVersion() {
    return extensionVersion.intValueExact();
  }

  public byte[] appletVersion() {
    return appletVersion.getOctets();
  }

  public byte[] platformInformation() {
    return Asn1Util.fromAsn1(platformInformation);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(extensionVersion, appletVersion, platformInformation);
  }

  public static InstanceCACertificateExtensionSchema fromEncoded(byte[] encoded)
      throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static InstanceCACertificateExtensionSchema fromAsn1(Asn1Sequence seq)
      throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer extensionVersion = seq.getNonNegativeIntegerAt(0);
    Asn1OctetString appletVersion = seq.getOctetStringAt(1);
    int index = 2;
    Asn1OctetString platformInformation = seq.notHasOctetString(index) ? null
        : seq.getOctetStringAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new InstanceCACertificateExtensionSchema(extensionVersion, appletVersion,
        platformInformation);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    extensionVersion.toStringNoLineSep(buf, indentLevel, "extension_version", true);
    appletVersion.toStringNoLineSep(buf, indentLevel, "applet_version", true);
    if (platformInformation != null) {
      platformInformation.toStringNoLineSep(buf, indentLevel, "platform_information", true);
    }
    return deleteLastNewLine(buf);
  }
}
