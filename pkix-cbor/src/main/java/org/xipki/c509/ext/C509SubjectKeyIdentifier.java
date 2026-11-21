// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The subject key identifier extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SubjectKeyIdentifier extends C509ExtnValue {

  private final byte[] keyId;

  public C509SubjectKeyIdentifier(byte[] keyId) {
    if (keyId == null || keyId.length == 0) {
      throw new IllegalArgumentException("keyId must not be empty");
    }
    this.keyId = keyId.clone();
  }

  public byte[] keyId() {
    return keyId.clone();
  }

  public static C509SubjectKeyIdentifier read(CborDecoder in) throws CodecException {
    return new C509SubjectKeyIdentifier(in.readByteString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(keyId);
  }

  @Override
  protected void render(C509TextTree out) {
    out.hex("key id", keyId);
  }

  @Override
  public String label() {
    return "Subject Key Identifier";
  }

}
