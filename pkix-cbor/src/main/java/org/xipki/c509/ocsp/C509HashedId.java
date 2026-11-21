// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.codec.Hex;
import org.xipki.codec.util.Args;

import java.util.Arrays;

/**
 * HashedId20: the low-order 20 bytes of a hash value, used in OCSP to identify a certificate
 * (issuer, requestor or responder certificate).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509HashedId {

  private final byte[] value;

  public C509HashedId(byte[] value) {
    Args.notNull(value, "value");
    Args.range(value.length, "value.length", 8, 64);
    this.value = value;
  }

  /** The left-most 20 bytes of a hash value. */
  public static C509HashedId truncate(byte[] hash, int truncatedLength) {
    return new C509HashedId(truncatedLength == hash.length
        ? hash : Arrays.copyOfRange(hash, 0, truncatedLength));
  }

  public byte[] value() {
    return value.clone();
  }

  byte[] raw() {
    return value;
  }

  public boolean match(byte[] hash) {
    return Arrays.equals(value, 0, value.length, hash, 0, value.length);
  }

  public int length() {
    return value.length;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    return (o instanceof C509HashedId) && Arrays.equals(value, ((C509HashedId) o).value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return Hex.encode(value);
  }

}
