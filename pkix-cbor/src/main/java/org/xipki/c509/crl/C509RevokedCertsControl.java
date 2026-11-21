// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * RevokedCertsControl: describes the fixed-size entries of a revocation group
 * (draft-liao-cose-c509-revocation-01, Section 6.2).
 *
 * <pre>
 * RevokedCertsControl = [
 *   flags               : uint32,
 *   serialNumberLength  : 1..20,
 *   dateLength          : uint .le 8,
 *   baseDate            : ~time,
 * ]
 * </pre>
 * <p>
 * An entry is the serial number, the date as offset to the base date (if the date length is
 * not zero) and, for revoked certificates, one reason byte (if flagged).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509RevokedCertsControl extends C509CborItem {

  private static final long FLAG_SORTED = 1;

  private static final long FLAG_REASONS = 2;

  private final long flags;

  private final int serialLength;

  private final int dateLength;

  private final long baseDate;

  public C509RevokedCertsControl(long flags, int serialLength, int dateLength, long baseDate) {
    if (flags < 0) {
      throw new IllegalArgumentException("negative flags");
    }
    if (serialLength < 1 || serialLength > 20) {
      throw new IllegalArgumentException("serialLength out of range: " + serialLength);
    }
    if (dateLength < 0 || dateLength > 8) {
      throw new IllegalArgumentException("dateLength out of range: " + dateLength);
    }
    this.flags = flags;
    this.serialLength = serialLength;
    this.dateLength = dateLength;
    this.baseDate = baseDate;
  }

  public static C509RevokedCertsControl of(
      boolean sorted, boolean withReasons, int serialLength,
      int dateLength, long baseDateSecond) {
    return new C509RevokedCertsControl(
        (sorted ? FLAG_SORTED : 0) | (withReasons ? FLAG_REASONS : 0),
        serialLength, dateLength, baseDateSecond);
  }

  public long flags() {
    return flags;
  }

  public boolean isSorted() {
    return (flags & FLAG_SORTED) != 0;
  }

  public boolean hasReasons() {
    return (flags & FLAG_REASONS) != 0;
  }

  public int serialLength() {
    return serialLength;
  }

  public int dateLength() {
    return dateLength;
  }

  public long baseDate() {
    return baseDate;
  }

  /** Size of one revoked-certificate entry. */
  public int revokedEntrySize() {
    return serialLength + dateLength + (hasReasons() ? 1 : 0);
  }

  /** Size of one removed-from-CRL entry. */
  public int removedEntrySize() {
    return serialLength + dateLength;
  }

  public static String flagsText(long flags) {
    return ((flags & FLAG_SORTED) != 0 ? "sorted" : "unsorted") + ", "
        + ((flags & FLAG_REASONS) != 0 ? "with" : "no") + " reason (0x"
        + Long.toHexString(flags) + ")";
  }

  public static C509RevokedCertsControl read(CborDecoder in) throws CodecException {
    in.readArrayLength(4);
    long flags = in.readLong();
    int serialLength = in.readInt();
    int dateLength = in.readInt();
    return new C509RevokedCertsControl(flags, serialLength, dateLength, in.readLong());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(4);
    out.writeLong(flags);
    out.writeInt(serialLength);
    out.writeInt(dateLength);
    out.writeLong(baseDate);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("flags", flagsText(flags))
        .kv("serial number length", serialLength)
        .kv("date length", dateLength)
        .kv("base date", baseDate);
  }

}
