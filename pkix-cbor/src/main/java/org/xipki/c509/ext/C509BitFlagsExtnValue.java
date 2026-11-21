// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.List;

/**
 * An extension value made of named bits, encoded as an unsigned integer.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509BitFlagsExtnValue extends C509ExtnValue {

  private final int bits;

  protected C509BitFlagsExtnValue(int bits) {
    if (bits <= 0) {
      throw new IllegalArgumentException("at least one bit must be set: " + bits);
    }
    this.bits = bits;
  }

  /**
   * Names of the bits, index i names the bit {@code 1 << i}.
   */
  protected abstract String[] bitNames();

  public final int bits() {
    return bits;
  }

  /**
   * Checks whether all bit of the mask is set.
   */
  public final boolean has(int mask) {
    return (bits & mask) == mask;
  }

  public final boolean hasBitIndex(int index) {
    return index >= 0 && index < bitNames().length && (bits & (1 << index)) != 0;
  }

  public final List<String> names() {
    String[] names = bitNames();
    List<String> list = new ArrayList<>(Integer.bitCount(bits));
    for (int i = 0; i < names.length; i++) {
      if ((bits & (1 << i)) != 0 && names[i] != null) {
        list.add(names[i]);
      }
    }
    return list;
  }

  static int combine(int[] values, boolean asIndexes) {
    if (values == null || values.length == 0) {
      throw new IllegalArgumentException("no flags given");
    }
    int result = 0;
    for (int v : values) {
      if (asIndexes) {
        if (v < 0 || v > 30) {
          throw new IllegalArgumentException("bit index out of range: " + v);
        }
        result |= 1 << v;
      } else {
        if (v <= 0) {
          throw new IllegalArgumentException("invalid flag mask: " + v);
        }
        result |= v;
      }
    }
    return result;
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(bits);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line("0x" + Integer.toHexString(bits) + ": " + names());
  }

}
