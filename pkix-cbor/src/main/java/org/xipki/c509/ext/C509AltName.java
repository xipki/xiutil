// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * The subject / issuer alternative name extension. A single DNS name is encoded as a bare
 * text string.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AltName extends C509ExtnValue {

  private final C509GeneralNames names;

  public C509AltName(C509GeneralNames names) {
    this.names = Args.notNull(names, "names");
  }

  public static C509AltName of(C509GeneralName... names) {
    return new C509AltName(C509GeneralNames.of(names));
  }

  public C509GeneralNames names() {
    return names;
  }

  public static C509AltName read(CborDecoder in) throws CodecException {
    return in.peekType().isTextString()
        ? of(C509GeneralName.dns(in.readTextString()))
        : new C509AltName(C509GeneralNames.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509GeneralName first = names.first();
    if (names.size() == 1 && first.tag() == ConstGeneralNameTag.dNSName) {
      out.writeTextString(first.text());
    } else {
      names.encode(out);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(names);
  }

  @Override
  public String label() {
    return "Alternative Name";
  }

}
