// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * The nine fields shared by a CRL and its CRL info
 * (draft-liao-cose-c509-revocation-01, Section 6.2).
 *
 * <pre>
 * CRLInfoData = (
 *   crlType                : 0, ; int16
 *   signatureAlgorithm     : IntAlgorithmIdentifier,
 *   authoritySubject       : NameVariant,
 *   authorityKeyIdentifier : bytes,
 *   crlNumber              : CRLNumber,
 *   thisUpdate             : ~time,
 *   nextUpdate             : uint63 / null,
 *   baseCrlNumber          : CRLNumber / null,
 *   crlExtensions          : IntExtensions,
 * )
 *
 * CRLNumber = 1..9223372036854775807
 * </pre>
 *
 * nextUpdate is encoded as the number of seconds from thisUpdate.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CRLInfoData extends C509CborItem {

  public static final int TYPE_BASIC = 0;

  static final int FIELD_COUNT = 9;

  private final int signatureAlgorithm;

  private final C509NameVariant authority;

  private final byte[] authorityKeyId;

  private final long crlNumber;

  private final Instant thisUpdate;

  private final Instant nextUpdate;

  private final Long baseCrlNumber;

  private final C509Extensions extensions;

  /**
   * @param authorityKeyId the subject key identifier of the CRL issuer, must not be null or
   *                       empty.
   * @param baseCrlNumber  the number of the base CRL for a delta CRL, otherwise null.
   */
  public C509CRLInfoData(
      int signatureAlgorithm, C509NameVariant authority,
      byte[] authorityKeyId, long crlNumber, Instant thisUpdate,
      Instant nextUpdate, Long baseCrlNumber, C509Extensions extensions) {
    if (signatureAlgorithm < Short.MIN_VALUE || signatureAlgorithm > Short.MAX_VALUE) {
      throw new IllegalArgumentException("signatureAlgorithm out of range");
    }
    if (crlNumber <= 0) {
      throw new IllegalArgumentException("crlNumber must be positive");
    }
    this.signatureAlgorithm = signatureAlgorithm;
    this.authority = Args.notNull(authority, "authority");
    if (Args.notNull(authorityKeyId, "authorityKeyId").length == 0) {
      throw new IllegalArgumentException("authorityKeyId must not be empty");
    }
    this.authorityKeyId = authorityKeyId.clone();
    this.crlNumber = crlNumber;
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate")
        .truncatedTo(ChronoUnit.SECONDS);
    this.nextUpdate = nextUpdate == null ? null : nextUpdate.truncatedTo(ChronoUnit.SECONDS);
    if (this.nextUpdate != null && this.nextUpdate.isBefore(this.thisUpdate)) {
      throw new IllegalArgumentException("nextUpdate is before thisUpdate");
    }
    this.baseCrlNumber = baseCrlNumber;
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
  }

  public int signatureAlgorithm() {
    return signatureAlgorithm;
  }

  public C509NameVariant authority() {
    return authority;
  }

  public byte[] authorityKeyId() {
    return C509Cbor.copy(authorityKeyId);
  }

  public long crlNumber() {
    return crlNumber;
  }

  public Instant thisUpdate() {
    return thisUpdate;
  }

  public Instant nextUpdate() {
    return nextUpdate;
  }

  public Long baseCrlNumber() {
    return baseCrlNumber;
  }

  public boolean isDelta() {
    return baseCrlNumber != null;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  static C509CRLInfoData read(CborDecoder in) throws CodecException {
    int type = in.readInt();
    if (type != TYPE_BASIC) {
      throw new CodecException("unsupported CRL type " + type);
    }
    int sigAlg = in.readInt();
    C509NameVariant authority = C509NameVariant.read(in);
    byte[] keyId = in.readByteString();
    if (keyId == null || keyId.length == 0) {
      throw new CodecException("authorityKeyIdentifier must not be null or empty");
    }
    long crlNumber = in.readLong();
    Instant thisUpdate = in.readUnwrappedInstant();
    Long delta = in.readLongObj();
    Instant nextUpdate = delta == null ? null : thisUpdate.plusSeconds(delta);
    Long baseCrlNumber = in.readLongObj();
    return new C509CRLInfoData(sigAlg, authority, keyId, crlNumber, thisUpdate, nextUpdate,
        baseCrlNumber, C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(TYPE_BASIC);
    out.writeInt(signatureAlgorithm);
    authority.encode(out);
    out.writeByteString(authorityKeyId);
    out.writeLong(crlNumber);
    out.writeUnwrappedTime(thisUpdate);
    if (nextUpdate == null) {
      out.writeNull();
    } else {
      out.writeLong(nextUpdate.getEpochSecond() - thisUpdate.getEpochSecond());
    }
    out.writeLongObj(baseCrlNumber);
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm))
        .item("authority", authority)
        .hex("authority key id", authorityKeyId)
        .kv("CRL number", crlNumber)
        .kv("this update", thisUpdate)
        .kv("next update", nextUpdate)
        .kv("base CRL number", baseCrlNumber)
        .item("extensions", extensions);
  }

}
