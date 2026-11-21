// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ipres;

import org.xipki.codec.util.Args;
import org.xipki.codec.util.Rfc3779IPAddress;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An RFC 3779 IP address bit string: the significant bytes and the number of unused bits in
 * the last byte.
 * <p>
 * Two CBOR forms exist: a byte string {@code unusedBits || bytes}, and, for short values, the
 * integer {@code (unusedBits + 1) || bytes} read as unsigned big-endian number.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509IpBits {

  private final int unusedBits;

  private final byte[] bytes;

  public C509IpBits(int unusedBits, byte[] bytes) {
    if (unusedBits < 0 || unusedBits > 7) {
      throw new IllegalArgumentException("unusedBits out of range: " + unusedBits);
    }
    this.unusedBits = unusedBits;
    this.bytes = Args.notNull(bytes, "bytes").clone();
  }

  public int unusedBits() {
    return unusedBits;
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  /** Whether the integer form can be used. */
  boolean fitsInteger() {
    return bytes.length < 8;
  }

  long toInteger() {
    byte[] tagged = new byte[bytes.length + 1];
    tagged[0] = (byte) (unusedBits + 1);
    System.arraycopy(bytes, 0, tagged, 1, bytes.length);
    return new BigInteger(1, tagged).longValueExact();
  }

  static C509IpBits ofInteger(long value) {
    if (value <= 0) {
      throw new IllegalArgumentException("invalid integer IP address " + value);
    }
    byte[] tagged = BigInteger.valueOf(value).toByteArray();
    return new C509IpBits((tagged[0] & 0xFF) - 1, Arrays.copyOfRange(tagged, 1, tagged.length));
  }

  byte[] toOctets() {
    byte[] tagged = new byte[bytes.length + 1];
    tagged[0] = (byte) unusedBits;
    System.arraycopy(bytes, 0, tagged, 1, bytes.length);
    return tagged;
  }

  static C509IpBits ofOctets(byte[] tagged) {
    return new C509IpBits(tagged[0] & 0xFF, Arrays.copyOfRange(tagged, 1, tagged.length));
  }

  String text(int afi, Rfc3779IPAddress.Context context) {
    return new Rfc3779IPAddress(bytes, unusedBits).toString(afi, context);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    return (o instanceof C509IpBits) && unusedBits == ((C509IpBits) o).unusedBits
        && Arrays.equals(bytes, ((C509IpBits) o).bytes);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(bytes) + unusedBits;
  }

}
