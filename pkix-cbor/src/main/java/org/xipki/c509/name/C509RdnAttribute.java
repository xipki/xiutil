// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.util.ToStringUtil;

import java.util.Objects;

/**
 * One RDN attribute (draft-ietf-cose-cbor-encoded-cert-21, Section 3.1.4).
 * The absolute value of the int attributeType is the value of the C509 RDN
 * Attributes registry; the sign represents the string type: positive for
 * utf8String, negative for printableString.
 *
 * <pre>
 * RDNAttribute = (
 *     ( attributeType: int, attributeValue: SpecialText ) //
 *     ( attributeType: ~oid, attributeValue: bytes )
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class C509RdnAttribute extends CborEncodable {

  private final long attributeType;

  private final SpecialText attributeValue;

  public C509RdnAttribute(long attributeType, String attributeValue) {
    this(attributeType, SpecialText.ofText(attributeValue));
  }

  public C509RdnAttribute(long attributeType, SpecialText attributeValue) {
    this.attributeType = Args.notNegative(attributeType, "attributeType");
    this.attributeValue = Args.notNull(attributeValue, "attributeValue");
  }

  public long attributeType() {
    return attributeType;
  }

  public SpecialText attributeValue() {
    return attributeValue;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeLong(attributeType);
    attributeValue.encode(encoder);
  }

  @Override
  public int hashCode() {
    int ret = Long.hashCode(attributeType);
    return ret * 31 + attributeValue.hashCode();
  }

  public String attributeValueAsText() {
    return attributeValue.asText();
  }

  public static C509RdnAttribute read(CborDecoder decoder) throws CodecException {
    int attributeType = decoder.readInt();
    return new C509RdnAttribute(attributeType, SpecialText.read(decoder));
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509RdnAttribute)) {
      return false;
    }

    C509RdnAttribute b = (C509RdnAttribute) obj;

    return attributeType == b.attributeType
        && Objects.equals(attributeValue, b.attributeValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    String title = ConstRDNAttributeType.describe(attributeType);
    return ToStringUtil.appendIndent(buf, indentLevel, title + ": " + attributeValueAsText());
  }

}
