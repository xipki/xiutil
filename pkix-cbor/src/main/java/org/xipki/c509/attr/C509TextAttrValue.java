// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * An attribute whose value is a single text string, e.g. gender or place of birth.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TextAttrValue extends C509AttrValue {

  private final String text;

  public C509TextAttrValue(String text) {
    this.text = Args.notBlank(text, "text");
  }

  public String text() {
    return text;
  }

  static C509TextAttrValue read(CborDecoder in) throws CodecException {
    return new C509TextAttrValue(in.readTextString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeTextString(text);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(text);
  }

  @Override
  public String label() {
    return "TextAttrValue";
  }

}
