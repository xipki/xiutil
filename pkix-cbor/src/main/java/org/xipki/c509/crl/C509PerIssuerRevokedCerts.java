// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * PerIssuerRevokedCerts: the revoked and the removed-from-CRL certificates of one issuer
 * (draft-liao-cose-c509-revocation-01, Section 6.2).
 *
 * <pre>
 * PerIssuerRevokedCerts = (
 *   issuer                 : NameVariant / null,
 *   revokedCertsControl    : RevokedCertsControl / null,
 *   extensions             : IntExtensions,
 *   revokedCerts           : bytes .size (1..2147483647) / null,
 *   removedFromCRLCerts    : bytes .size (1..2147483647) / null,
 * )
 * </pre>
 *
 * The issuer is null for certificates of the CRL issuer itself.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerRevokedCerts extends C509CborItem {

  /** A group without any content. */
  public static final C509PerIssuerRevokedCerts BLANK =
      new C509PerIssuerRevokedCerts(null, null, C509Extensions.EMPTY, null, null);

  /**
   * One decoded entry.
   */
  public static final class Entry {

    private final BigInteger serialNumber;

    private final Long date;

    private final Integer reason;

    Entry(BigInteger serialNumber, Long date, Integer reason) {
      this.serialNumber = serialNumber;
      this.date = date;
      this.reason = reason;
    }

    public BigInteger serialNumber() {
      return serialNumber;
    }

    /** The revocation (or removal) date (epoch second), or null. */
    public Long date() {
      return date;
    }

    /** The revocation reason code, or null. */
    public Integer reason() {
      return reason;
    }

    @Override
    public String toString() {
      return "0x" + serialNumber.toString(16).toUpperCase()
          + (date == null ? "" : ", " + Instant.ofEpochSecond(date))
          + (reason == null ? "" : ", " + C509RevocationReason.nameOf(reason));
    }

  }

  private final C509NameVariant issuer;

  private final C509RevokedCertsControl layout;

  private final C509Extensions extensions;

  private final byte[] revoked;

  private final byte[] removed;

  /**
   * @param issuer     the issuer, null for the CRL issuer.
   * @param layout     the entry layout, required if there is any entry.
   * @param extensions the extensions, null for none.
   * @param revoked    the concatenated revoked-certificate entries, may be null.
   * @param removed    the concatenated removed-from-CRL entries, may be null.
   */
  public C509PerIssuerRevokedCerts(
      C509NameVariant issuer, C509RevokedCertsControl layout,
      C509Extensions extensions, byte[] revoked, byte[] removed) {
    this.issuer = issuer;
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.revoked = C509Cbor.emptyToNull(revoked);
    this.removed = C509Cbor.emptyToNull(removed);
    if (this.revoked == null && this.removed == null) {
      this.layout = null;
    } else {
      this.layout = Args.notNull(layout, "layout");
      check(this.revoked, layout.revokedEntrySize(), "revoked");
      check(this.removed, layout.removedEntrySize(), "removed");
    }
  }

  private static void check(byte[] entries, int entrySize, String what) {
    if (entries != null && entries.length % entrySize != 0) {
      throw new IllegalArgumentException(what + ": length " + entries.length
          + " is not a multiple of the entry size " + entrySize);
    }
  }

  public boolean isBlank() {
    return issuer == null && layout == null && extensions.isEmpty();
  }

  public C509NameVariant issuer() {
    return issuer;
  }

  public C509RevokedCertsControl layout() {
    return layout;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public byte[] revokedBytes() {
    return C509Cbor.copy(revoked);
  }

  public byte[] removedBytes() {
    return C509Cbor.copy(removed);
  }

  public List<Entry> revoked() {
    return revoked == null ? List.of() : entries(revoked, true);
  }

  public List<Entry> removed() {
    return removed == null ? List.of() : entries(removed, false);
  }

  private List<Entry> entries(byte[] data, boolean withReason) {
    int sn = layout.serialLength();
    int dl = layout.dateLength();
    boolean reasons = withReason && layout.hasReasons();
    int size = sn + dl + (reasons ? 1 : 0);
    List<Entry> list = new ArrayList<>(data.length / size);
    for (int off = 0; off < data.length; off += size) {
      BigInteger serial = new BigInteger(1, data, off, sn);
      // TODO: replace BigInteger with quick convert
      Long date = dl == 0 ? null : layout.baseDate() +
          new BigInteger(1, data, off + sn, dl).longValueExact();
      Integer reason = reasons ? (data[off + sn + dl] & 0xFF) : null;
      list.add(new Entry(serial, date, reason));
    }
    return Collections.unmodifiableList(list);
  }

  public static C509PerIssuerRevokedCerts read(CborDecoder in) throws CodecException {
    C509NameVariant issuer = C509Cbor.orNull(in, C509NameVariant::read);
    C509RevokedCertsControl layout = C509Cbor.orNull(in, C509RevokedCertsControl::read);
    C509Extensions extensions = C509Extensions.read(in);
    byte[] revoked = C509Cbor.readBytesOrNull(in);
    return new C509PerIssuerRevokedCerts(issuer, layout, extensions, revoked,
        C509Cbor.readBytesOrNull(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeObject(issuer);
    out.writeObject(layout);
    extensions.encode(out);
    C509Cbor.writeBytesOrNull(out, revoked);
    C509Cbor.writeBytesOrNull(out, removed);
  }

  @Override
  protected void render(C509TextTree out) {
    if (issuer == null) {
      out.kv("issuer", "CRL issuer");
    } else {
      out.item("issuer", issuer);
    }
    out.item("layout", layout)
        .item("extensions", extensions);
    if (revoked != null) {
      out.nest("revoked").lines(revoked());
    }
    if (removed != null) {
      out.nest("removed from CRL").lines(removed());
    }
  }

}
