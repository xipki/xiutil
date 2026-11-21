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

/**
 * SingleCertRequest (draft-liao-cose-c509-revocation-01, Section 7.4.1).
 *
 * <pre>
 * SingleCertRequest = (
 *   serialNumber     : bytes .size (1..20),
 *   extensions       : IntExtensions,
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SingleCertRequest extends C509CborItem {

  static final int WIDTH = 2;

  private final BigInteger serialNumber;

  private final C509Extensions extensions;

  public C509SingleCertRequest(BigInteger serialNumber, C509Extensions extensions) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  static C509SingleCertRequest read(CborDecoder in) throws CodecException {
    return new C509SingleCertRequest(
        new BigInteger(1, in.readByteString()), C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(BigIntegers.asUnsignedByteArray(serialNumber));
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("serial number", "0x" + serialNumber.toString(16))
        .item("extensions", extensions);
  }

}
