// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Encodes the {@code Name} structure (draft-ietf-cose-cbor-encoded-cert-21, Section 3.1.4),
 * either as a list of RDN attributes or, if Name contains a single 'common name' attribute
 * with attributeType = +1, as just the SpecialText containing the attribute value.
 *
 * <pre>
 * Name = [ * RDNAttribute ] / SpecialText
 * RDNAttribute = (
 *     ( attributeType: int, attributeValue: SpecialText ) //
 *     ( attributeType: ~oid, attributeValue: bytes )
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class C509Name extends CborEncodable {

  private static final Asn1Oid OID_TLS_C509 = new Asn1Oid("1.3.6.1.4.1.45522.4.1");

  private final C509RdnAttribute[] attributes;

  // "-symbol is not allowed in the value.
  public C509Name(String text) {
    text = Args.notNull(text, "text").trim();
    if (text.isEmpty()) {
      attributes = new C509RdnAttribute[0];
      return;
    }

    List<C509RdnAttribute> list = new LinkedList<>();
    AtomicInteger fromIndex = new AtomicInteger(0);

    try {
      do {
        String[] nameValue = nextToken(text, fromIndex);
        String name  = nameValue[0];
        String value = nameValue[1];

        long code = ConstRDNAttributeType.getCode(name);
        list.add(new C509RdnAttribute(code, value));
      } while (fromIndex.get() < text.length());
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("invalid name '" + text + "'", e);
    }

    this.attributes = list.toArray(new C509RdnAttribute[0]);
  }

  public C509Name(List<C509RdnAttribute> attributes) {
    this.attributes = Args.noNullElements(attributes, "attributes")
        .toArray(new C509RdnAttribute[0]);
  }

  public C509Name(C509RdnAttribute... attributes) {
    this.attributes = Args.noNullElements(attributes, "attributes");
  }

  public int size() {
    return attributes.length;
  }

  public C509RdnAttribute getAttributeAt(int index) {
    return attributes[index];
  }

  public C509RdnAttribute[] getAttributes() {
    return Arrays.copyOf(attributes, attributes.length);
  }

  public boolean hasAttribute(long attributeType) {
    for (C509RdnAttribute m : attributes) {
      if (m.attributeType() == attributeType) {
        return true;
      }
    }
    return false;
  }

  public C509RdnAttribute[] getAttribute(long attributeType) {
    int size = 0;
    for (C509RdnAttribute m : attributes) {
      if (m.attributeType() == attributeType) {
        size++;
      }
    }

    if (size == 0) {
      return null;
    }

    C509RdnAttribute[] ret = new C509RdnAttribute[size];
    int index = 0;
    for (C509RdnAttribute m : attributes) {
      if (m.attributeType() == attributeType) {
        ret[index++] = m;
      }
    }
    return ret;
  }

  public C509RdnAttribute getFirstAttribute(long attributeType) {
    for (C509RdnAttribute m : attributes) {
      if (m.attributeType() == attributeType) {
        return m;
      }
    }
    return null;
  }

  public long[] attributeTypes() {
    long[] types = new long[attributes.length];

    int index = 0;
    for (C509RdnAttribute attr : attributes) {
      long type = attr.attributeType();
      if (!contains(types, type, index)) {
        types[index++] = type;
      }
    }

    return index == attributes.length ? types : Arrays.copyOf(types, index);
  }

  private static boolean contains(long[] array, long value, int toExclude) {
    for (int i = 0; i < toExclude; i++) {
      if (array[i] == value) {
        return true;
      }
    }
    return false;
  }

  private static String[] nextToken(String str, AtomicInteger fromIndex) {
    int strLen = str.length();

    ignoreLeadingChars(str, fromIndex, ' ', ',', '\t');

    // find index of '='
    int equalsIndex = str.indexOf('=', fromIndex.get());
    String name = str.substring(fromIndex.get(), equalsIndex).trim();

    fromIndex.set(equalsIndex + 1);
    ignoreLeadingChars(str, fromIndex, ' ');

    int valueFromIndex = fromIndex.get();
    int valueEndIndex = -1;

    boolean quoted = str.charAt(valueFromIndex) == '"';
    if (quoted) {
      fromIndex.incrementAndGet();
      valueFromIndex++;

      for (int i = fromIndex.get(); i < strLen; i++) {
        if (str.charAt(i) == '"') {
          valueEndIndex = i;
          break;
        }
      }

      if (valueEndIndex == -1) {
        throw new IllegalArgumentException("invalid name '" + str + "'");
      }

      // ignore all letters before the next ","
      fromIndex.set(valueEndIndex + 1);
      for (; fromIndex.get() < strLen; fromIndex.incrementAndGet()) {
        if (str.charAt(fromIndex.get()) == ',') {
          fromIndex.incrementAndGet();
          break;
        }
      }
    } else {
      for (int i = fromIndex.get(); i < strLen; i++) {
        if (str.charAt(i) == ',') {
          valueEndIndex = i;
          break;
        }
      }

      if (valueEndIndex == -1) {
        // last attribute
        valueEndIndex = strLen;
      }

      fromIndex.set(valueEndIndex + 1);
    }

    String value = str.substring(valueFromIndex, valueEndIndex).trim();
    return new String[] {name, value};
  }

  private static void ignoreLeadingChars(String str, AtomicInteger fromIndex, char... chars) {
    // ignore leading spaces
    int strLen = str.length();
    for (int i = fromIndex.get(); i < strLen; i++) {
      char c = str.charAt(i);
      boolean ignore = false;
      for (char c0 : chars) {
        if (c == c0) {
          ignore = true;
          break;
        }
      }

      if (ignore) {
        fromIndex.incrementAndGet();
      } else {
        break;
      }
    }
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    if (attributes.length == 1) {
      C509RdnAttribute attr = attributes[0];
      if (ConstRDNAttributeType.commonName == attr.attributeType()) {
        attr.attributeValue().encode(encoder);
        return;
      }
    }

    int num = attributes.length;
    encoder.writeArrayStart(2 * num);
    for (C509RdnAttribute attr : attributes) {
      attr.encode(encoder);
    }
  }

  public byte[] toTlsX500Name() {
    // SEQUENCE
    //   SET
    //     SEQUENCE
    //       OID
    //       OCTET STRING: CBOR encoded name
    byte[] encodedC509 = getEncoded();
    return new Asn1Sequence(
        new Asn1Set(new Asn1Sequence(OID_TLS_C509, new Asn1OctetString(encodedC509)))
    ).getEncoded();
  }

  public static C509Name fromTlsX500Name(byte[] encoded) throws CodecException {
    Asn1Sequence seq0 = Asn1Sequence.fromEncoded(encoded);
    if (seq0.size() != 1) {
      throw new CodecException("invalid TlsX500Name for C509Name");
    }

    Asn1Set set1 = seq0.getSetAt(0);
    if (set1.size() != 1) {
      throw new CodecException("invalid TlsX500Name for C509Name");
    }

    Asn1Sequence seq2 = set1.getSequenceAt(0);
    if (seq2.size() != 2) {
      throw new CodecException("invalid TlsX500Name for C509Name");
    }

    Asn1Oid oid = seq2.getOidAt(0);
    if (oid.equals(OID_TLS_C509)) {
      throw new CodecException("invalid TlsX500Name for C509Name");
    }

    byte[] encodedC509Name = seq0.getOctetStringAt(1).getOctets();
    return parse(encodedC509Name);
  }

  public static C509Name parse(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return read(decoder);
    }
  }

  public static C509Name read(CborDecoder decoder) throws CodecException {
    CborType type = decoder.peekType();
    C509RdnAttribute[] attributes;

    if (type.isArray()) {
      int arrayLen = decoder.readArrayLength();
      if ((arrayLen & 0x01) != 0) {
        throw new CodecException("Name: number of elements is not even");
      }

      int numAttrs = arrayLen >> 1;
      attributes = new C509RdnAttribute[numAttrs];

      for (int i = 0; i < numAttrs; i++) {
        attributes[i] = C509RdnAttribute.read(decoder);
      }
    } else {
      SpecialText attrValue = SpecialText.read(decoder);
      attributes = new C509RdnAttribute[] {
          new C509RdnAttribute(ConstRDNAttributeType.commonName, attrValue)};
    }

    return new C509Name(attributes);
  }

  @Override
  public int hashCode() {
    int hashCode = 0;
    for (C509RdnAttribute attr : attributes) {
      hashCode *= 31;
      hashCode += attr.hashCode();
    }
    return hashCode;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (attributes == null || attributes.length == 0) {
      return ToStringUtil.appendIndent(buf, indentLevel, "<EMPTY>");
    }
    return ToStringUtil.appendIndent(buf, indentLevel, getNameText());
  }

  @Override
  public String toString() {
    return getNameText();
  }

  public String getNameText() {
    if (attributes == null || attributes.length == 0) {
      return "";
    }

    StringBuilder buf = new StringBuilder();
    for (int i = 0; i < attributes.length; i++) {
      C509RdnAttribute attr = attributes[i];

      String attrName = ConstRDNAttributeType.getShortName(attr.attributeType());

      String value = attr.attributeValueAsText();
      if (value.indexOf(',') != -1) {
        value = "\"" + value + "\"";
      }

      buf.append(attrName).append("=").append(value);
      if (i != attributes.length - 1) {
        buf.append(", ");
      }
    }

    return buf.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509Name)) {
      return false;
    }

    return Arrays.equals(attributes, ((C509Name) obj).attributes);
  }

  public String getCanonicalizedText() {
    List<Long> types = new LinkedList<>();

    int size = size();
    for (int i = 0; i < size; i++) {
      long type = getAttributeAt(i).attributeType();
      if (!types.contains(type)) {
        types.add(type);
      }
    }

    Collections.sort(types);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < types.size(); i++) {
      long type = types.get(i);
      if (i > 0) {
        sb.append(",");
      }
      sb.append(type).append("=");

      C509RdnAttribute[] attrs = getAttribute(type);
      for (C509RdnAttribute attr : attrs) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(type).append("=");
        sb.append(attr.attributeValueAsText());
      }
    }

    return sb.toString();
  }

}
