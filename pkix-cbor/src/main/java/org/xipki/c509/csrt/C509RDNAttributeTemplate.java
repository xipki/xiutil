// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csrt;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.c509.name.SpecialText;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * One RDN attribute of the template.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509RDNAttributeTemplate extends C509CborItem {

  private final long type;

  private final int minOccurs;

  private final int maxOccurs;

  private final SpecialText value;

  /**
   * @param value the fixed value, or null if the requester chooses it.
   */
  public C509RDNAttributeTemplate(long type, int minOccurs, int maxOccurs, SpecialText value) {
    if (type < 0) {
      throw new IllegalArgumentException("negative attribute type " + type);
    }
    this.type = type;
    this.minOccurs = minOccurs;
    this.maxOccurs = maxOccurs;
    this.value = value;
  }

  /** An attribute that occurs exactly once with the given value. */
  public static C509RDNAttributeTemplate fixed(long type, String value) {
    return new C509RDNAttributeTemplate(type, 1, 1, SpecialText.ofText(value));
  }

  /** An attribute whose value the requester chooses. */
  public static C509RDNAttributeTemplate free(long type, int minOccurs, int maxOccurs) {
    return new C509RDNAttributeTemplate(type, minOccurs, maxOccurs, null);
  }

  public long type() {
    return type;
  }

  public int minOccurs() {
    return minOccurs;
  }

  public int maxOccurs() {
    return maxOccurs;
  }

  public SpecialText value() {
    return value;
  }

  static C509RDNAttributeTemplate read(CborDecoder in) throws CodecException {
    int type = in.readInt();
    int min = in.readInt();
    int max = in.readInt();
    return new C509RDNAttributeTemplate(
        type, min, max, C509Cbor.orUndefined(in, SpecialText::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(type);
    out.writeInt(minOccurs);
    out.writeInt(maxOccurs);
    C509Cbor.writeOrUndefined(out, value);
  }

  String text() {
    String v = value == null ? "*" : value.asText();
    if (v.indexOf(',') >= 0) {
      v = "\"" + v + "\"";
    }
    return ConstRDNAttributeType.getShortName(type) + "{" + minOccurs + ".." + maxOccurs
        + "}=" + v;
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(text());
  }

}
