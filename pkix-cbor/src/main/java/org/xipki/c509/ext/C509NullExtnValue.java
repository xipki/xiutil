// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The extension value CBOR null, used by extensions without content (e.g. OCSP no-check) and
 * by extensions where null carries a meaning (e.g. "inherit" for the AS identifiers).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509NullExtnValue extends C509ExtnValue {

  public static final C509NullExtnValue INSTANCE = new C509NullExtnValue();

  private C509NullExtnValue() {
  }

  public static C509NullExtnValue read(CborDecoder in) throws CodecException {
    in.readNull();
    return INSTANCE;
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeNull();
  }

  @Override
  protected void render(C509TextTree out) {
    out.line("null");
  }

  @Override
  public String label() {
    return "Null";
  }

}
