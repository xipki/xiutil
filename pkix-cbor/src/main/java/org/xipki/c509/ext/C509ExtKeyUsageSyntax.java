// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.Arrays;
import java.util.List;

/**
 * The extended key usage extension. A single usage is encoded as a bare integer.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ExtKeyUsageSyntax extends C509ExtnValue {

  private final long[] usages;

  public C509ExtKeyUsageSyntax(long... usages) {
    if (usages == null || usages.length == 0) {
      throw new IllegalArgumentException("usages must not be empty");
    }
    this.usages = usages.clone();
  }

  public C509ExtKeyUsageSyntax(List<Long> usages) {
    Args.notEmptyAndNoNullElements(usages, "usages");
    this.usages = new long[usages.size()];
    for (int i = 0; i < this.usages.length; i++) {
      this.usages[i] = usages.get(i);
    }
  }

  public long[] usages() {
    return usages.clone();
  }

  public boolean contains(long usage) {
    return Arrays.stream(usages).anyMatch(u -> u == usage);
  }

  public static C509ExtKeyUsageSyntax read(CborDecoder in) throws CodecException {
    if (!in.peekType().isArray()) {
      return new C509ExtKeyUsageSyntax(in.readLong());
    }
    long[] ids = new long[in.readArrayLength()];
    for (int i = 0; i < ids.length; i++) {
      ids[i] = in.readLong();
    }
    return new C509ExtKeyUsageSyntax(ids);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (usages.length == 1) {
      out.writeLong(usages[0]);
      return;
    }
    out.writeArrayStart(usages.length);
    for (long u : usages) {
      out.writeLong(u);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    for (long u : usages) {
      out.line(ConstExtendedKeyUsage.describe(u));
    }
  }

  @Override
  public String label() {
    return "Extended Key Usage";
  }

}
