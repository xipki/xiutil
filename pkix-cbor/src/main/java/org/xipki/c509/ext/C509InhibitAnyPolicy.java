// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The inhibit anyPolicy extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509InhibitAnyPolicy extends C509ExtnValue {

  private final int skipCerts;

  public C509InhibitAnyPolicy(int skipCerts) {
    if (skipCerts < 0) {
      throw new IllegalArgumentException("negative skipCerts " + skipCerts);
    }
    this.skipCerts = skipCerts;
  }

  public int skipCerts() {
    return skipCerts;
  }

  public static C509InhibitAnyPolicy read(CborDecoder in) throws CodecException {
    return new C509InhibitAnyPolicy(in.readInt());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(skipCerts);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("skip certs", skipCerts);
  }

  @Override
  public String label() {
    return "Inhibit anyPolicy";
  }

}
