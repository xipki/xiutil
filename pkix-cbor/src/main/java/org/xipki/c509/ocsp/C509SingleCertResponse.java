// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.BigIntegers;

import java.math.BigInteger;
import java.time.Instant;

/**
 * SingleCertResponse (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * SingleCertResponse = (
 *   serialNumber     : bytes .size (1..20),
 *   certStatus       : CertStatus,
 *   thisUpdate       : nint / 0,
 *   nextUpdate       : uint63 / null,
 *   extensions       : IntExtensions,
 * )
 * </pre>
 *
 * Both times are seconds relative to producedAt: thisUpdate is not positive, nextUpdate not
 * negative.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SingleCertResponse extends C509CborItem {

  static final int WIDTH = 5;

  private final BigInteger serialNumber;

  private final C509CertStatus status;

  private final long thisUpdate;

  private final Long nextUpdate;

  private final C509Extensions extensions;

  public C509SingleCertResponse(
      BigInteger serialNumber, C509CertStatus status, long thisUpdate,
      Long nextUpdate, C509Extensions extensions) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.status = Args.notNull(status, "status");
    if (thisUpdate > 0) {
      throw new IllegalArgumentException("thisUpdate is after producedAt");
    }
    if (nextUpdate != null && nextUpdate < 0) {
      throw new IllegalArgumentException("nextUpdate is before producedAt");
    }
    this.thisUpdate = thisUpdate;
    this.nextUpdate = nextUpdate;
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public C509CertStatus status() {
    return status;
  }

  /** Seconds relative to producedAt. */
  public long thisUpdate() {
    return thisUpdate;
  }

  /** Seconds relative to producedAt, or null. */
  public Long nextUpdate() {
    return nextUpdate;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public C509CertStatusInfo getCertStatus(Instant baseTime) {
    long baseEpoch = baseTime.getEpochSecond();
    return new C509CertStatusInfo(serialNumber, status,
        Instant.ofEpochSecond(baseEpoch + thisUpdate),
        (nextUpdate == null ? null : Instant.ofEpochSecond(baseEpoch + nextUpdate)),
        extensions);
  }

  static C509SingleCertResponse read(CborDecoder in) throws CodecException {
    BigInteger serial = new BigInteger(1, in.readByteString());
    C509CertStatus status = C509CertStatus.read(in);
    long thisUpdate = in.readLong();
    Long nextUpdate = in.readLongObj();
    return new C509SingleCertResponse(
        serial, status, thisUpdate, nextUpdate, C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(BigIntegers.asUnsignedByteArray(serialNumber));
    status.encode(out);
    out.writeLong(thisUpdate);
    out.writeLongObj(nextUpdate);
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("serial", "0x" + serialNumber.toString(16)).item("status", status)
        .kv("this update", thisUpdate + "s").kv("next update", nextUpdate)
        .item("extensions", extensions);
  }

}
