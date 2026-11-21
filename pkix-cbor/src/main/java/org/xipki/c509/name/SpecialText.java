// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborTaggedObject;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * Represents the {@code SpecialText} type used by RDN attribute values
 * (draft-ietf-cose-cbor-encoded-cert-21, Section 3.1.4). A text string of even length of at least 2
 * containing only '0'-'9' or 'a'-'f' is encoded as a CBOR byte string; an EUI-64 of the form
 * "HH-HH-HH-HH-HH-HH-HH-HH" as a MAC address with CBOR tag 48; otherwise as a CBOR text string.
 *
 * <pre>
 * SpecialText = text / bytes / tag
 *
 * tag = #6
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SpecialText extends CborEncodable {

  private final String text;

  private final byte[] bytes;

  private final CborTaggedObject tag;

  private SpecialText(String text, byte[] bytes, CborTaggedObject tag) {
    int num = (text != null) ? 1 : 0;
    num += (bytes != null) ? 1 : 0;
    num += (tag != null) ? 1 : 0;
    if (num != 1) {
      throw new IllegalArgumentException("exactly one of text, bytes and tag shall be non-null");
    }

    this.text = text;
    this.bytes = bytes;
    this.tag = tag;
  }

  public String text() {
    return text;
  }

  public byte[] bytes() {
    return bytes;
  }

  public CborTaggedObject tag() {
    return tag;
  }

  public static SpecialText ofText(String attrValue) {
    boolean evenLowerHex = hasPositiveEvenNumberOfLowerHexChars(attrValue);

    if (evenLowerHex) {
      byte[] bytes = Hex.decode(attrValue);
      return new SpecialText(null, bytes, null);
    }

    int len = attrValue.length();
    boolean eui = true;
    if (len == 23) {
      for (int i = 0; i < 23; i++) {
        char c = attrValue.charAt(i);
        if (i % 3 == 2) {
          if (c != '-') {
            eui = false;
            break;
          }
        } else {
          if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            eui = false;
            break;
          }
        }
      }
    } else {
      eui = false;
    }

    if (eui) {
      // EUI-64
      boolean isMac48 = attrValue.indexOf("FF-FE") == 9;
      byte[] bytes = new byte[isMac48 ? 6 : 8];

      String hex = attrValue.replace("-", "");
      if (isMac48) {
        byte[] decoded = Hex.decode(hex);
        System.arraycopy(decoded, 0, bytes, 0, 3);
        System.arraycopy(decoded, 5, bytes, 3, 3);
      } else {
        Hex.decode(hex, bytes, 0);
      }

      CborTaggedObject tag = new CborTaggedObject(48, bytes);
      return new SpecialText(null, null, tag);
    }

    return new SpecialText(attrValue, null, null);
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    if (text != null) {
      encoder.writeTextString(text);
    } else if (bytes != null) {
      encoder.writeByteString(bytes);
    } else {
      tag.encode(encoder);
    }
  }

  @Override
  public int hashCode() {
    if (text != null) {
      return text.hashCode();
    } else if (bytes != null) {
      return Arrays.hashCode(bytes);
    } else {
      return tag.hashCode();
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf, indentLevel, asText());
  }

  public String asText() {
    if (text != null) {
      return text;
    } else if (bytes != null) {
      return Hex.encode(bytes);
    } else {
      long tagNo = tag.tag();
      if (tagNo == 48) {
        byte[] tagValue = (byte[]) tag.value();
        boolean eui48 = tagValue.length == 6;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < tagValue.length; i++) {
          if (i != 0) {
            sb.append("-");
          }
          sb.append(Hex.encodeUpper(tagValue[i]));

          if (eui48 && i == 2) {
            sb.append("-FF-FE");
          }
        }
        return sb.toString();
      } else {
        return "<unknown-tag-" + tagNo + ">";
      }
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof SpecialText)) {
      return false;
    }

    SpecialText b = (SpecialText) obj;
    if (text != null) {
      return text.equals(b.text);
    } else if (bytes != null) {
      return Arrays.equals(bytes, b.bytes);
    } else {
      return tag.equals(b.tag);
    }
  }

  public static SpecialText read(CborDecoder decoder) throws CodecException {
    CborType type = decoder.peekType();
    if (type.isTextString()) {
      return new SpecialText(decoder.readTextString(), null, null);
    } else if (type.isByteString()) {
      return new SpecialText(null, decoder.readByteString(), null);
    } else if (type.isTag()) {
      CborTaggedObject obj = (CborTaggedObject) decoder.readNext();
      return new SpecialText(null, null, obj);
    } else {
      throw new CodecException("unexpected Cbor Type " + type + " in attribute");
    }
  }

  private static boolean hasPositiveEvenNumberOfLowerHexChars(String str) {
    int len = str.length();
    if (len == 0) {
      return false;
    }

    if (len % 2 != 0) {
      return false;
    }

    for (int i = 0; i < len; i++) {
      char c = str.charAt(i);
      boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');

      if (!isHex) {
        return false;
      }
    }

    return true;
  }

}
