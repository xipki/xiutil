// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstPolicyQualifier;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * A policy qualifier, e.g. a CPS URI or a user notice.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PolicyQualifierInfo extends C509CborItem {

  private final int id;

  private final String text;

  public C509PolicyQualifierInfo(int id, String text) {
    this.id = id;
    this.text = Args.notNull(text, "text");
    if (text.trim().isEmpty()) {
      throw new IllegalArgumentException("text must not be blank");
    }
  }

  public static C509PolicyQualifierInfo cps(String uri) {
    return new C509PolicyQualifierInfo(ConstPolicyQualifier.cps, uri);
  }

  public static C509PolicyQualifierInfo userNotice(String text) {
    return new C509PolicyQualifierInfo(ConstPolicyQualifier.unotice, text);
  }

  public int id() {
    return id;
  }

  public String text() {
    return text;
  }

  static C509PolicyQualifierInfo read(CborDecoder in) throws CodecException {
    return new C509PolicyQualifierInfo(in.readInt(), in.readTextString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(id);
    out.writeTextString(text);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv(ConstPolicyQualifier.describe(id), text);
  }

}
