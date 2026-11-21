// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ipres;

import org.xipki.codec.util.Args;

import java.util.Objects;

/**
 * An address prefix or an address range.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509IPAddressOrRange {

  private final C509IpBits low;

  private final C509IpBits high;

  private C509IPAddressOrRange(C509IpBits low, C509IpBits high) {
    this.low = Args.notNull(low, "low");
    this.high = high;
  }

  public static C509IPAddressOrRange prefix(C509IpBits prefix) {
    return new C509IPAddressOrRange(prefix, null);
  }

  public static C509IPAddressOrRange range(C509IpBits min, C509IpBits max) {
    return new C509IPAddressOrRange(min, Args.notNull(max, "max"));
  }

  public boolean isRange() {
    return high != null;
  }

  /** The prefix, or the lower end of the range. */
  public C509IpBits low() {
    return low;
  }

  /** The upper end of the range, or the prefix itself. */
  public C509IpBits high() {
    return high == null ? low : high;
  }

  boolean fitsInteger() {
    return low.fitsInteger() && (high == null || high.fitsInteger());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    return (o instanceof C509IPAddressOrRange) && low.equals(((C509IPAddressOrRange) o).low)
        && Objects.equals(high, ((C509IPAddressOrRange) o).high);
  }

  @Override
  public int hashCode() {
    return Objects.hash(low, high);
  }

}
