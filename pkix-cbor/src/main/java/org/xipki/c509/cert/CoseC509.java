// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.cert;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * COSE_C509: one certificate as a byte string, or several as an array of byte strings.
 *
 * @author Lijun Liao (xipki)
 */
public final class CoseC509 extends C509CborItem {

  private final List<C509Certificate> certificates;

  public CoseC509(List<C509Certificate> certificates) {
    this.certificates = C509Cbor.nonEmpty(C509Cbor.frozen(certificates, "certificates"),
        "certificates");
  }

  public static CoseC509 of(C509Certificate... certificates) {
    return new CoseC509(Arrays.asList(certificates));
  }

  public List<C509Certificate> certificates() {
    return certificates;
  }

  public C509Certificate first() {
    return certificates.get(0);
  }

  public C509Certificate getAtIndex(int index) {
    return certificates.get(index);
  }

  public int size() {
    return certificates.size();
  }

  public static CoseC509 parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, CoseC509::read);
  }

  public static CoseC509 read(CborDecoder in) throws CodecException {
    if (!in.peekType().isArray()) {
      return of(C509Certificate.parse(in.readByteString()));
    }
    int n = in.readArrayLength();
    List<C509Certificate> list = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      list.add(C509Certificate.parse(in.readByteString()));
    }
    return new CoseC509(list);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (certificates.size() > 1) {
      out.writeArrayStart(certificates.size());
    }
    for (C509Certificate c : certificates) {
      out.writeByteString(c.getEncoded());
    }
  }

  @Override
  protected void render(C509TextTree out) {
    for (C509Certificate c : certificates) {
      out.kv("certificate", c.subject().getNameText() + ", serial 0x"
          + c.serialNumber().toString(16));
    }
  }

}
