// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The OCSP request extension listing the response types a client accepts.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AcceptableResponseTypes extends C509ExtnValue {

  private final int[] types;

  public C509AcceptableResponseTypes(int... types) {
    if (types == null || types.length == 0) {
      throw new IllegalArgumentException("types must not be empty");
    }
    this.types = types.clone();
  }

  public int[] types() {
    return types.clone();
  }

  public static C509AcceptableResponseTypes read(CborDecoder in) throws CodecException {
    return new C509AcceptableResponseTypes(in.readInts());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(types.length);
    for (int t : types) {
      out.writeLong(t);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    for (int t : types) {
      out.line("response type " + t);
    }
  }

  @Override
  public String label() {
    return "Acceptable OCSP Response Types";
  }

}
