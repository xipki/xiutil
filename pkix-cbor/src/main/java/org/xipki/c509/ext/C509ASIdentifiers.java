// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ipres.C509ASIdOrRange;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.List;

/**
 * The autonomous system identifiers extension (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * ASIdOrRange = uint / [min:uint, max:uint]
 * ASIdentifiers = [ + ASIdOrRange ] / null
 * </pre>
 *
 * Every block is written relative to the upper end of its predecessor: an AS number as
 * integer, a range as {@code [min, max - min]}. The extension value CBOR null
 * ({@link C509NullExtnValue}) means "inherit".
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ASIdentifiers extends C509ExtnValue {

  private final List<C509ASIdOrRange> blocks;

  public C509ASIdentifiers(List<C509ASIdOrRange> blocks) {
    if (blocks == null || blocks.isEmpty()) {
      throw new IllegalArgumentException("blocks must not be empty");
    }
    this.blocks = List.copyOf(blocks);
  }

  public static C509ASIdentifiers of(C509ASIdOrRange... blocks) {
    return new C509ASIdentifiers(List.of(blocks));
  }

  public List<C509ASIdOrRange> blocks() {
    return blocks;
  }

  /**
   * Reads the value. The CBOR null (inherit) is handled by the extension catalog.
   */
  public static C509ASIdentifiers read(CborDecoder in) throws CodecException {
    int n = in.readArrayLength();
    List<C509ASIdOrRange> list = new ArrayList<>(n);
    long base = 0;
    for (int i = 0; i < n; i++) {
      CborType type = in.peekType();
      C509ASIdOrRange block;
      if (type.isInt()) {
        block = C509ASIdOrRange.id(base + in.readLong());
      } else if (type.isArray()) {
        in.readArrayLength(2);
        long min = base + in.readLong();
        block = C509ASIdOrRange.range(min, min + in.readLong());
      } else {
        throw new CodecException("AS identifiers: unexpected CBOR type " + type);
      }
      list.add(block);
      base = block.max();
    }
    return new C509ASIdentifiers(list);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(blocks.size());
    long base = 0;
    for (C509ASIdOrRange b : blocks) {
      if (b.min() < base) {
        throw new CodecException("AS blocks are not in ascending order");
      }
      if (b.isRange()) {
        out.writeArrayStart(2);
        out.writeLong(b.min() - base);
        out.writeLong(b.max() - b.min());
      } else {
        out.writeLong(b.min() - base);
      }
      base = b.max();
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.lines(blocks);
  }

  @Override
  public String label() {
    return "AS Identifiers";
  }

}
