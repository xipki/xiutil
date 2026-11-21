// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.attr.C509Attributes;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * The subject directory attributes extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SubjectDirectoryAttributes extends C509ExtnValue {

  private final C509Attributes attributes;

  public C509SubjectDirectoryAttributes(C509Attributes attributes) {
    this.attributes = Args.notNull(attributes, "attributes");
  }

  public C509Attributes attributes() {
    return attributes;
  }

  public static C509SubjectDirectoryAttributes read(CborDecoder in) throws CodecException {
    return new C509SubjectDirectoryAttributes(C509Attributes.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    attributes.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(attributes);
  }

  @Override
  public String label() {
    return "Subject Directory Attributes";
  }

}
