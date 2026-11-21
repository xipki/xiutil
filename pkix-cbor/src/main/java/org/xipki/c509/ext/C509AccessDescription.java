// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * An access description.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AccessDescription extends C509CborItem {

  private final int method;

  private final String uri;

  public C509AccessDescription(int method, String uri) {
    if (method < Short.MIN_VALUE || method > Short.MAX_VALUE) {
      throw new IllegalArgumentException("access method out of range: " + method);
    }
    this.method = method;
    this.uri = Args.notNull(uri, "uri");
    if (uri.trim().isEmpty()) {
      throw new IllegalArgumentException("uri must not be blank");
    }
  }

  public int method() {
    return method;
  }

  public String uri() {
    return uri;
  }

  static C509AccessDescription read(CborDecoder in) throws CodecException {
    return new C509AccessDescription(in.readInt(), in.readTextString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeInt(method);
    out.writeTextString(uri);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv(ConstAccessMethod.name(method), uri);
  }

}
