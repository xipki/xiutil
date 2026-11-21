// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.ext.C509ExpiredCertsOnCRL;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Collects the entries of one revocation group. Created by {@link C509CRLBuilder#group}.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerRevokedCertsBuilder {

  private static final class Item {

    private final BigInteger serial;

    // seconds since EPOCH
    private final Long date;

    private final int reason;

    private Item(BigInteger serial, Long date, int reason) {
      if (Args.notNull(serial, "serialNumber").signum() < 0) {
        throw new IllegalArgumentException("negative serial number");
      }
      this.serial = serial;
      this.date = date;
      this.reason = reason;
    }

  }

  private final C509NameVariant issuer;

  private final boolean delta;

  private final boolean sorted;

  private final boolean withDates;

  private final boolean withReasons;

  private final Map<Long, C509Extension> extensions = new LinkedHashMap<>();

  private final List<Item> revoked = new ArrayList<>();

  private final List<Item> removed = new ArrayList<>();

  C509PerIssuerRevokedCertsBuilder(
      C509NameVariant issuer, boolean delta, boolean sorted,
      boolean withDates, boolean withReasons) {
    this.issuer = issuer;
    this.delta = delta;
    this.sorted = sorted;
    this.withDates = withDates;
    this.withReasons = withReasons;
  }

  C509NameVariant issuer() {
    return issuer;
  }

  boolean hasOptions(boolean sorted, boolean withDates, boolean withReasons) {
    return this.sorted == sorted && this.withDates == withDates
        && this.withReasons == withReasons;
  }

  String options() {
    return "sorted=" + sorted + ", withDates=" + withDates + ", withReasons=" + withReasons;
  }

  /**
   * @param date   the revocation date, required if the group carries dates.
   * @param reason the revocation reason code, see {@link C509RevocationReason}.
   */
  public C509PerIssuerRevokedCertsBuilder revoked(
      BigInteger serialNumber, Instant date, int reason) {
    if (!C509RevocationReason.isRevocationCode(reason)) {
      throw new IllegalArgumentException("invalid revocation reason " + reason);
    }
    revoked.add(new Item(serialNumber, dated(date), reason));
    return this;
  }

  /**
   * @param date   the revocation date (EPOCH seconds), required if the group carries dates.
   * @param reason the revocation reason code, see {@link C509RevocationReason}.
   */
  public C509PerIssuerRevokedCertsBuilder revoked(
      BigInteger serialNumber, Long date, int reason) {
    if (!C509RevocationReason.isRevocationCode(reason)) {
      throw new IllegalArgumentException("invalid revocation reason " + reason);
    }
    revoked.add(new Item(serialNumber, dated(date), reason));
    return this;
  }

  /**
   * Adds a certificate that has been removed from the CRL; only for delta CRLs.
   */
  public C509PerIssuerRevokedCertsBuilder removed(BigInteger serialNumber, Instant date) {
    if (!delta) {
      throw new IllegalStateException("removed entries are only allowed in delta CRLs");
    }
    removed.add(new Item(serialNumber, dated(date), 0));
    return this;
  }

  public C509PerIssuerRevokedCertsBuilder removed(BigInteger serialNumber, Long date) {
    if (!delta) {
      throw new IllegalStateException("removed entries are only allowed in delta CRLs");
    }
    removed.add(new Item(serialNumber, dated(date), 0));
    return this;
  }

  private Long dated(Instant date) {
    if (!withDates) {
      return null;
    }
    return Args.notNull(date, "date").getEpochSecond();
  }

  private Long dated(Long date) {
    if (!withDates) {
      return null;
    }
    return Args.notNull(date, "date");
  }

  public C509PerIssuerRevokedCertsBuilder expiredCertsOnCrl(Instant since) {
    return extension(C509Extension.nonCritical(ConstExtensionId.expiredCertsOnCRL,
        new C509ExpiredCertsOnCRL(since)));
  }

  public C509PerIssuerRevokedCertsBuilder extension(
      long id, boolean critical, C509ExtnValue value) {
    return extension(new C509Extension(id, critical, value));
  }

  public C509PerIssuerRevokedCertsBuilder extension(C509Extension extension) {
    if (extensions.putIfAbsent(extension.id(), extension) != null) {
      throw new IllegalArgumentException("duplicate extension "
          + ConstExtensionId.describe(extension.id()));
    }
    return this;
  }

  /**
   * @param fallbackBase the base date if the group carries no dates.
   */
  C509PerIssuerRevokedCerts build(long fallbackBase) {
    C509Extensions extns = new C509Extensions(extensions.values());
    if (revoked.isEmpty() && removed.isEmpty()) {
      return new C509PerIssuerRevokedCerts(issuer, null, extns, null, null);
    }

    List<Item> all = new ArrayList<>(revoked);
    all.addAll(removed);

    int serialBits = all.stream().mapToInt(i -> i.serial.bitLength()).max().getAsInt();
    int serialLen = Math.max(1, (serialBits + 7) / 8);

    long base = fallbackBase;
    int dateLen = 0;
    if (withDates) {
      base = all.stream().map(i -> i.date).min(Comparator.naturalOrder()).get();
      Long max = all.stream().map(i -> i.date).max(Comparator.naturalOrder()).get();
      long span = max - base;
      dateLen = Math.max(1, (64 - Long.numberOfLeadingZeros(span) + 7) / 8);
    }

    C509RevokedCertsControl layout =
        C509RevokedCertsControl.of(sorted, withReasons, serialLen, dateLen, base);
    return new C509PerIssuerRevokedCerts(issuer, layout, extns,
        pack(revoked, layout, withReasons), pack(removed, layout, false));
  }

  private byte[] pack(List<Item> items, C509RevokedCertsControl layout, boolean reasons) {
    List<Item> list = new ArrayList<>(items);
    if (sorted) {
      list.sort(Comparator.comparing(i -> i.serial));
    }

    int sn = layout.serialLength();
    int dl = layout.dateLength();
    int size = sn + dl + (reasons ? 1 : 0);
    long base = layout.baseDate();
    byte[] out = new byte[list.size() * size];
    int off = 0;
    for (Item i : list) {
      putUnsigned(i.serial, out, off, sn);
      if (dl > 0) {
        putUnsigned(BigInteger.valueOf(i.date - base), out, off + sn, dl);
      }
      if (reasons) {
        out[off + sn + dl] = (byte) i.reason;
      }
      off += size;
    }
    return out;
  }

  /** Writes the value big-endian, right-aligned into {@code len} bytes. */
  private static void putUnsigned(BigInteger value, byte[] buf, int off, int len) {
    byte[] raw = value.toByteArray();
    int skip = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
    int n = raw.length - skip;
    if (n > len) {
      throw new IllegalArgumentException("value does not fit into " + len + " bytes");
    }
    System.arraycopy(raw, skip, buf, off + len - n, n);
  }

}
