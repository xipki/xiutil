// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborMap;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * The value of an extension without a dedicated class, kept as {@link CborEncodedItem}.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509RawExtnValue extends C509ExtnValue {

  private final CborEncodedItem raw;

  public C509RawExtnValue(CborEncodedItem raw) {
    this.raw = Args.notNull(raw, "raw");
  }

  /**
   * @param data generic CBOR data, see {@link CborDecoder#readNext()}, encoded
   *             deterministically, see {@link CborMap#deepSorted(Object)}.
   * @throws IllegalArgumentException if a map key cannot be encoded, or a map has duplicate keys.
   */
  public C509RawExtnValue(Object data) {
    this(CborEncodedItem.ofData(data));
  }

  public CborEncodedItem raw() {
    return raw;
  }

  /**
   * The value as generic CBOR data, see {@link CborEncodedItem#data()}.
   */
  public Object data() throws CodecException {
    return raw.data();
  }

  public static C509RawExtnValue read(CborDecoder in) throws CodecException {
    return new C509RawExtnValue(in.readEncodedItem());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    raw.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(raw.toDiagnostic());
  }

  @Override
  public String label() {
    return "Unrecognized Extension Value";
  }

}
