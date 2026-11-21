// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.crl.C509RevocationReason;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * The status of one certificate (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * CertStatus = 0        ; good
 *            / 1        ; not-issued (issuer recognized,
 *                       ;   serial number not issued)
 *            / 2        ; unknown (issuer not recognized)
 *            / RevokedInfo
 * RevokedInfo = [
 *   revocationTime   : ~time,
 *   revocationReason : uint8,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertStatus extends C509CborItem {

  /**
   * The kind of status.
   */
  public enum Kind {
    GOOD(0, "good"),
    NOT_ISSUED(1, "not-issued"),
    UNKNOWN(2, "unknown"),
    REVOKED(-1, "revoked");

    private final int code;

    private final String text;

    Kind(int code, String text) {
      this.code = code;
      this.text = text;
    }

    public int code() {
      return code;
    }

    public String text() {
      return text;
    }

    public static Kind ofCode(int code) {
      for (Kind k : values()) {
        if (k.code == code && k != REVOKED) {
          return k;
        }
      }
      throw new IllegalArgumentException("unknown certificate status " + code);
    }
  }

  public static final C509CertStatus GOOD = new C509CertStatus(Kind.GOOD, null, 0);

  public static final C509CertStatus NOT_ISSUED = new C509CertStatus(Kind.NOT_ISSUED, null, 0);

  public static final C509CertStatus UNKNOWN = new C509CertStatus(Kind.UNKNOWN, null, 0);

  private final Kind kind;

  private final Instant revocationTime;

  private final int reason;

  private C509CertStatus(Kind kind, Instant revocationTime, int reason) {
    this.kind = kind;
    this.revocationTime = revocationTime;
    this.reason = reason;
  }

  public static C509CertStatus of(Kind kind) {
    switch (kind) {
      case GOOD:
        return GOOD;
      case NOT_ISSUED:
        return NOT_ISSUED;
      case UNKNOWN:
        return UNKNOWN;
      default:
        throw new IllegalArgumentException("use revoked(...) for revoked certificates");
    }
  }

  public static C509CertStatus revoked(Instant time, int reason) {
    if (!C509RevocationReason.isRevocationCode(reason)) {
      throw new IllegalArgumentException("invalid revocation reason " + reason);
    }
    return new C509CertStatus(Kind.REVOKED,
        Args.notNull(time, "time").truncatedTo(ChronoUnit.SECONDS), reason);
  }

  public Kind kind() {
    return kind;
  }

  /** The revocation time, or null if not revoked. */
  public Instant revocationTime() {
    return revocationTime;
  }

  /** The revocation reason; only meaningful if revoked. */
  public int reason() {
    return reason;
  }

  public static C509CertStatus read(CborDecoder in) throws CodecException {
    if (in.peekType().isInt()) {
      return of(Kind.ofCode(in.readInt()));
    }
    in.readArrayLength(2);
    Instant time = in.readUnwrappedInstant();
    return revoked(time, in.readInt());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (kind != Kind.REVOKED) {
      out.writeLong(kind.code);
      return;
    }
    out.writeArrayStart(2);
    out.writeUnwrappedTime(revocationTime);
    out.writeInt(reason);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(kind != Kind.REVOKED ? kind.text
        : "revoked at " + revocationTime + " (" + C509RevocationReason.nameOf(reason) + ")");
  }

}
