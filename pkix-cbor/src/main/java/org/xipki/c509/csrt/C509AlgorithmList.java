// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csrt;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

/**
 * A non-empty array of algorithm identifiers, as used by the request template.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AlgorithmList extends C509CborItem {

  private final ConstRegistry registry;

  private final int[] algorithms;

  private C509AlgorithmList(ConstRegistry registry, int[] algorithms) {
    this.registry = Args.notNull(registry, "registry");
    if (algorithms == null || algorithms.length == 0) {
      throw new IllegalArgumentException("algorithms must not be empty");
    }
    this.algorithms = algorithms.clone();
  }

  public static C509AlgorithmList signatureAlgorithms(int... algorithms) {
    return new C509AlgorithmList(ConstRegistry.SIGNATURE_ALGORITHM, algorithms);
  }

  public static C509AlgorithmList keyAlgorithms(int... algorithms) {
    return new C509AlgorithmList(ConstRegistry.PUBLIC_KEY_ALGORITHM, algorithms);
  }

  public int[] algorithms() {
    return algorithms.clone();
  }

  static C509AlgorithmList read(CborDecoder in, ConstRegistry registry) throws CodecException {
    return new C509AlgorithmList(registry, C509Cbor.readIntArray(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeIntArray(out, algorithms);
  }

  @Override
  protected void render(C509TextTree out) {
    for (int a : algorithms) {
      out.line(registry.describe(a));
    }
  }

}
