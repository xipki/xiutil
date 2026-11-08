// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * ComponentIdentifierV11 ::= SEQUENCE {
 *     componentClass           ComponentClass,
 *     componentManufacturer    UTF8String (SIZE (1..STRMAX)),
 *     componentModel           UTF8String (SIZE (1..STRMAX)),
 *     componentSerial          [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentRevision        [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentManufacturerId  [2] IMPLICIT PrivateEnterpriseNumber OPTIONAL,
 *     fieldReplaceable         [3] IMPLICIT BOOLEAN OPTIONAL,
 *     componentAddresses       [4] IMPLICIT SEQUENCE(SIZE(1.. MAX)) OF ComponentAddress OPTIONAL,
 *     componentPlatformCert    [5] IMPLICIT CertificateIdentifier OPTIONAL,
 *     componentPlatformCertUri [6] IMPLICIT URIReference OPTIONAL,
 *     status                   [7] IMPLICIT AttributeStatus OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentIdentifierV11 extends Asn1Encodable {

  private final ComponentClass componentClass;

  private final Asn1Utf8String componentManufacturer;

  private final Asn1Utf8String componentModel;

  private final Asn1Utf8String componentSerial;

  private final Asn1Utf8String componentRevision;

  private final Asn1Oid componentManufacturerId;

  private final Boolean fieldReplaceable;

  private final ComponentAddresses componentAddresses;

  private final CertificateIdentifier componentPlatformCert;

  private final URIReference componentPlatformCertUri;

  private final AttributeStatus status;

  public ComponentIdentifierV11(
      ComponentClass componentClass, String componentManufacturer, String componentModel) {
    this(componentClass, componentManufacturer, componentModel,
        null, null, null, null, null, null, null, null);
  }

  public ComponentIdentifierV11(
      ComponentClass componentClass, Asn1Utf8String componentManufacturer,
      Asn1Utf8String componentModel) {
    this(componentClass, componentManufacturer, componentModel,
        null, null, null, null, null, null, null, null);
  }

  public ComponentIdentifierV11(
      ComponentClass componentClass, String componentManufacturer,
      String componentModel, String componentSerial,
      String componentRevision, Asn1Oid componentManufacturerId,
      Boolean fieldReplaceable, ComponentAddresses componentAddresses,
      CertificateIdentifier componentPlatformCert,
      URIReference componentPlatformCertUri, AttributeStatus status) {
    this(componentClass, Asn1Util.toUtf8String(componentManufacturer),
        Asn1Util.toUtf8String(componentModel), Asn1Util.toUtf8String(componentSerial),
        Asn1Util.toUtf8String(componentRevision), componentManufacturerId,
        fieldReplaceable, componentAddresses,
        componentPlatformCert, componentPlatformCertUri, status);
  }

  public ComponentIdentifierV11(
      ComponentClass componentClass, Asn1Utf8String componentManufacturer,
      Asn1Utf8String componentModel, Asn1Utf8String componentSerial,
      Asn1Utf8String componentRevision, Asn1Oid componentManufacturerId,
      Boolean fieldReplaceable, ComponentAddresses componentAddresses,
      CertificateIdentifier componentPlatformCert,
      URIReference componentPlatformCertUri, AttributeStatus status) {
    this.componentClass = Args.notNull(componentClass, "componentClass");
    this.componentManufacturer = Args.lengthRange(componentManufacturer,
        "componentManufacturer", 1, TcgConstants.STRMAX);
    this.componentModel = Args.lengthRange(componentModel,
        "componentModel", 1, TcgConstants.STRMAX);

    if (componentSerial != null) {
      Args.lengthRange(componentSerial,
              "componentSerial", 1, TcgConstants.STRMAX);
    }
    this.componentSerial = componentSerial;

    if (componentRevision != null) {
      Args.lengthRange(componentRevision,
              "componentRevision", 1, TcgConstants.STRMAX);
    }
    this.componentRevision = componentRevision;

    this.componentManufacturerId = componentManufacturerId;
    this.fieldReplaceable = fieldReplaceable;
    this.componentAddresses = componentAddresses;
    this.componentPlatformCert = componentPlatformCert;
    this.componentPlatformCertUri = componentPlatformCertUri;
    this.status = status;
  }

  public ComponentClass getComponentClass() {
    return componentClass;
  }

  public Asn1Utf8String getComponentManufacturer() {
    return componentManufacturer;
  }

  public Asn1Utf8String getComponentModel() {
    return componentModel;
  }

  public Asn1Utf8String getComponentSerial() {
    return componentSerial;
  }

  public Asn1Utf8String getComponentRevision() {
    return componentRevision;
  }

  public Asn1Oid getComponentManufacturerId() {
    return componentManufacturerId;
  }

  public Boolean getFieldReplaceable() {
    return fieldReplaceable;
  }

  public ComponentAddresses getComponentAddresses() {
    return componentAddresses;
  }

  public CertificateIdentifier getComponentPlatformCert() {
    return componentPlatformCert;
  }

  public URIReference getComponentPlatformCertUri() {
    return componentPlatformCertUri;
  }

  public AttributeStatus getStatus() {
    return status;
  }

  public String componentManufacturer() {
    return componentManufacturer.getString();
  }

  public String componentModel() {
    return componentModel.getString();
  }

  public String componentSerial() {
    return Asn1Util.fromAsn1(componentSerial);
  }

  public String componentRevision() {
    return Asn1Util.fromAsn1(componentRevision);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(componentClass, componentManufacturer, componentModel,
        (componentSerial == null) ? null
            : Asn1TaggedObject.newImplicit(0, componentSerial),
        (componentRevision == null) ? null
            : Asn1TaggedObject.newImplicit(1, componentRevision),
        (componentManufacturerId == null) ? null
            : Asn1TaggedObject.newImplicit(2, componentManufacturerId),
        (fieldReplaceable == null) ? null
            : Asn1TaggedObject.newImplicit(3, Asn1Boolean.getInstance(fieldReplaceable)),
        (componentAddresses == null) ? null
            : Asn1TaggedObject.newImplicit(4, componentAddresses),
        (componentPlatformCert == null) ? null
            : Asn1TaggedObject.newImplicit(5, componentPlatformCert),
        (componentPlatformCertUri == null) ? null
            : Asn1TaggedObject.newImplicit(6, componentPlatformCertUri),
        (status == null) ? null : Asn1TaggedObject.newImplicit(7, status));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    componentClass.toStringWithLineSep(buf, indentLevel, "componentClass", true);

    if (componentManufacturer != null) {
      componentManufacturer.toStringNoLineSep(buf, indentLevel, "componentManufacturer", true);
    }

    if (componentModel != null) {
      componentModel.toStringNoLineSep(buf, indentLevel, "componentModel", true);
    }

    if (componentSerial != null) {
      componentSerial.toStringNoLineSep(buf, indentLevel, "componentSerial", true);
    }

    if (componentRevision != null) {
      componentRevision.toStringNoLineSep(buf, indentLevel, "componentRevision", true);
    }

    if (componentManufacturerId != null) {
      componentManufacturerId.toStringNoLineSep(buf, indentLevel, "componentManufacturerId", true);
    }

    if (fieldReplaceable != null) {
      ToStringUtil.appendIndent(buf, indentLevel, "fieldReplaceable: " + fieldReplaceable + "\n");
    }

    if (componentAddresses != null) {
      componentAddresses.toStringWithLineSep(buf, indentLevel, "componentAddresses", true);
    }

    if (componentPlatformCert != null) {
      componentPlatformCert.toStringWithLineSep(buf, indentLevel, "componentPlatformCert", true);
    }

    if (componentPlatformCertUri != null) {
      componentPlatformCertUri.toStringNoLineSep(buf, indentLevel,
          "componentPlatformCertUri", true);
    }

    if (status != null) {
      status.toStringNoLineSep(buf, indentLevel, "status", true);
    }

    return deleteLastNewLine(buf);
  }

  public static ComponentIdentifierV11 fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ComponentIdentifierV11 fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 11);
    ComponentClass componentClass = ComponentClass.fromAsn1(seq.getSequenceAt(0));
    Asn1Utf8String manufacturer = seq.getUtf8StringAt(1);
    Asn1Utf8String model = seq.getUtf8StringAt(2);
    int index = 3;
    Asn1Utf8String serial = seq.isNotTaggedAt(index, 0) ? null
        : seq.getUtf8StringTaggedAt(index++, false);
    Asn1Utf8String revision = seq.isNotTaggedAt(index, 1) ? null
        : seq.getUtf8StringTaggedAt(index++, false);
    Asn1Oid manufacturerId = seq.isNotTaggedAt(index, 2) ? null
        : seq.getOidTaggedAt(index++, false);
    Boolean fieldReplaceable = seq.isNotTaggedAt(index, 3) ? null
        : seq.getBooleanTaggedAt(index++, false).isTrue();
    ComponentAddresses addresses = seq.isNotTaggedAt(index, 4) ? null
        : ComponentAddresses.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    CertificateIdentifier platformCert = seq.isNotTaggedAt(index, 5) ? null
        : CertificateIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    URIReference platformCertUri = seq.isNotTaggedAt(index, 6) ? null
        : URIReference.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    AttributeStatus status = seq.isNotTaggedAt(index, 7) ? null
        : AttributeStatus.fromAsn1(seq.getEnumeratedTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new ComponentIdentifierV11(componentClass, manufacturer, model, serial, revision,
        manufacturerId, fieldReplaceable, addresses, platformCert, platformCertUri, status);
  }

}
