// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * The extension request attribute of a certification request.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ExtensionRequest extends C509AttrValue {

  private final C509Extensions extensions;

  public C509ExtensionRequest(C509Extensions extensions) {
    this.extensions = Args.notNull(extensions, "extensions");
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public static C509ExtensionRequest read(CborDecoder in) throws CodecException {
    return new C509ExtensionRequest(C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(extensions);
  }

  @Override
  public String label() {
    return "Extension Request";
  }

}
