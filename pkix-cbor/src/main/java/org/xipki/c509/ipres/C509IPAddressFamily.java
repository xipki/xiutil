// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ipres;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Rfc3779IPAddress.Context;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * The address blocks of one address family (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * IPAddressFamily = (
 *   AFI: uint,
 *   SAFI: uint / null,
 *   IntIPAddressChoice / IPAddressChoice / null
 * )
 * </pre>
 *
 * A null block list means "inherit".
 * <p>
 * If every address fits, all addresses are written in the integer form, each relative to its
 * predecessor; otherwise all are written as byte strings.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509IPAddressFamily extends C509CborItem {

  public static final int AFI_IPV4 = 1;
  public static final int AFI_IPV6 = 2;

  public static final int SAFI_UNICAST = 1;
  public static final int SAFI_MULTICAST = 2;

  private static final Map<Integer, String> AFI_NAMES = Map.ofEntries(
      Map.entry(1, "IPv4"), Map.entry(2, "IPv6"), Map.entry(3, "NSAP"),
      Map.entry(4, "HDLC (8-bit multidrop)"), Map.entry(5, "BBN 1822"),
      Map.entry(6, "IEEE 802"), Map.entry(7, "E.163"), Map.entry(8, "E.164"),
      Map.entry(9, "F.69 (Telex)"), Map.entry(10, "X.121 (X.25, Frame Relay)"),
      Map.entry(11, "IPX"), Map.entry(12, "Appletalk"), Map.entry(13, "Decnet IV"),
      Map.entry(14, "Banyan Vines"), Map.entry(15, "E.164 NSAP subaddress"),
      Map.entry(16, "DNS"));

  /** Families without SAFI first, then by AFI and SAFI. */
  public static final Comparator<C509IPAddressFamily> ORDER =
      Comparator.comparing((C509IPAddressFamily f) -> f.safi != null)
          .thenComparingInt(f -> f.afi)
          .thenComparingInt(f -> f.safi == null ? 0 : f.safi);

  private final int afi;

  private final Integer safi;

  private final List<C509IPAddressOrRange> blocks;

  /**
   * @param afi    the address family identifier.
   * @param safi   the subsequent address family identifier, or null.
   * @param blocks the address blocks, or null to inherit them.
   */
  public C509IPAddressFamily(int afi, Integer safi, List<C509IPAddressOrRange> blocks) {
    if (afi < 0) {
      throw new IllegalArgumentException("negative afi " + afi);
    }
    if (safi != null && (safi < 0 || safi > 255)) {
      throw new IllegalArgumentException("safi out of range: " + safi);
    }
    this.afi = afi;
    this.safi = safi;
    this.blocks = blocks == null ? null
        : C509Cbor.nonEmpty(C509Cbor.frozen(blocks, "blocks"), "blocks");
  }

  public int afi() {
    return afi;
  }

  public Integer safi() {
    return safi;
  }

  public List<C509IPAddressOrRange> blocks() {
    return blocks;
  }

  public static String afiName(int afi) {
    return AFI_NAMES.getOrDefault(afi, "unknown");
  }

  public static String safiName(int safi) {
    return safi == SAFI_UNICAST ? "unicast" : safi == SAFI_MULTICAST ? "multicast" : "unknown";
  }

  // ----- encoding -----

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(afi);
    out.writeIntObj(safi);
    if (blocks == null) {
      out.writeNull();
      return;
    }

    boolean integers = blocks.stream().allMatch(C509IPAddressOrRange::fitsInteger);
    out.writeArrayStart(blocks.size());
    C509IpBits previous = null;
    for (C509IPAddressOrRange b : blocks) {
      if (b.isRange()) {
        out.writeArrayStart(2);
        writeBits(out, b.low(), previous, integers);
        writeBits(out, b.high(), b.low(), integers);
      } else {
        writeBits(out, b.low(), previous, integers);
      }
      previous = b.high();
    }
  }

  private static void writeBits(CborEncoder out, C509IpBits bits, C509IpBits base, boolean integers)
      throws CodecException {
    if (integers) {
      out.writeLong(bits.toInteger() - (base == null ? 0 : base.toInteger()));
    } else {
      out.writeByteString(bits.toOctets());
    }
  }

  public static C509IPAddressFamily read(CborDecoder in) throws CodecException {
    int afi = in.readInt();
    Integer safi = in.readIntObj();
    if (in.skipNull()) {
      return new C509IPAddressFamily(afi, safi, null);
    }

    int n = in.readArrayLength();
    CborType first = in.peekType();
    boolean integers = first.isInt() || (first.isArray() && in.peekTypes(2)[1].isInt());

    List<C509IPAddressOrRange> blocks = new ArrayList<>(n);
    C509IpBits previous = null;
    for (int i = 0; i < n; i++) {
      C509IPAddressOrRange block;
      if (in.peekType().isArray()) {
        in.readArrayLength(2);
        C509IpBits min = readBits(in, previous, integers);
        block = C509IPAddressOrRange.range(min, readBits(in, min, integers));
      } else {
        block = C509IPAddressOrRange.prefix(readBits(in, previous, integers));
      }
      blocks.add(block);
      previous = block.high();
    }
    return new C509IPAddressFamily(afi, safi, blocks);
  }

  private static C509IpBits readBits(CborDecoder in, C509IpBits base, boolean integers)
      throws CodecException {
    if (!integers) {
      return C509IpBits.ofOctets(in.readByteString());
    }
    return C509IpBits.ofInteger(in.readLong() + (base == null ? 0 : base.toInteger()));
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("AFI", afiName(afi) + " (" + afi + ")");
    if (safi != null) {
      out.kv("SAFI", safiName(safi) + " (" + safi + ")");
    }
    if (blocks == null) {
      out.line("inherit");
      return;
    }
    for (C509IPAddressOrRange b : blocks) {
      out.line(b.isRange()
          ? b.low().text(afi, Context.RANGE_MIN) + " - " + b.high().text(afi, Context.RANGE_MAX)
          : b.low().text(afi, Context.PREFIX));
    }
  }

}
