// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * The ACME Authorization extension (RFC 8737).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AcmeAuthorization extends C509ExtnValue {

  private final byte[] authorization;

  public C509AcmeAuthorization(byte[] authorization) {
    Args.notNull(authorization, "authorization");
    Args.equals(authorization.length, "authorization.length", 32);
    this.authorization = authorization.clone();
  }

  public byte[] authorization() {
    return authorization.clone();
  }

  public static C509AcmeAuthorization read(CborDecoder in) throws CodecException {
    return new C509AcmeAuthorization(in.readByteString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(authorization);
  }

  @Override
  protected void render(C509TextTree out) {
    out.hex("authorization", authorization);
  }

  @Override
  public String label() {
    return "ACME Authorization";
  }

}
