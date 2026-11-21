// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.time.Instant;

/**
 * The CRL extension expiredCertsOnCRL.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ExpiredCertsOnCRL extends C509ExtnValue {

  private final Instant since;

  public C509ExpiredCertsOnCRL(Instant since) {
    this.since = Args.notNull(since, "since");
    if (since.getEpochSecond() < 0) {
      throw new IllegalArgumentException("since must not be before 1970-01-01T00:00:00Z");
    }
  }

  public Instant since() {
    return since;
  }

  public static C509ExpiredCertsOnCRL read(CborDecoder in) throws CodecException {
    Instant since = in.readUnwrappedInstant();
    if (since == null || since.getEpochSecond() < 0) {
      throw new CodecException("ExpiredCertsOnCRL: not a non-negative time");
    }
    return new C509ExpiredCertsOnCRL(since);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeUnwrappedTime(since);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("since", since);
  }

  @Override
  public String label() {
    return "Expired Certificates on CRL";
  }

}
