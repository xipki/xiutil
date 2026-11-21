// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ipres;

/**
 * A single autonomous system number or a closed range of them.
 * The CBOR form depends on the predecessor and is produced by the AS identifiers extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ASIdOrRange {

  private final long min;

  private final long max;

  private final boolean range;

  private C509ASIdOrRange(long min, long max, boolean range) {
    if (min < 0 || max < min) {
      throw new IllegalArgumentException("invalid AS block " + min + "-" + max);
    }
    this.min = min;
    this.max = max;
    this.range = range;
  }

  public static C509ASIdOrRange id(long asNumber) {
    return new C509ASIdOrRange(asNumber, asNumber, false);
  }

  public static C509ASIdOrRange range(long min, long max) {
    return new C509ASIdOrRange(min, max, true);
  }

  public boolean isRange() {
    return range;
  }

  public long min() {
    return min;
  }

  public long max() {
    return max;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (!(o instanceof C509ASIdOrRange)) {
      return false;
    }
    C509ASIdOrRange b = (C509ASIdOrRange) o;
    return min == b.min && max == b.max && range == b.range;
  }

  @Override
  public int hashCode() {
    return Long.hashCode(min) * 31 + Long.hashCode(max) + (range ? 1 : 0);
  }

  @Override
  public String toString() {
    return range ? min + "-" + max : Long.toString(min);
  }

}
