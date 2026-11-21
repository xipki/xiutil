// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;

/**
 * One signature algorithm, optionally restricted to some public key algorithms.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PreferredSignatureAlgorithm extends C509CborItem {

  private final int signatureAlgorithm;

  private final int[] keyAlgorithms;

  public C509PreferredSignatureAlgorithm(int signatureAlgorithm, int... keyAlgorithms) {
    this.signatureAlgorithm = signatureAlgorithm;
    this.keyAlgorithms = (keyAlgorithms == null || keyAlgorithms.length == 0)
        ? null : keyAlgorithms.clone();
  }

  public int signatureAlgorithm() {
    return signatureAlgorithm;
  }

  /** The public key algorithms, or null if not restricted. */
  public int[] keyAlgorithms() {
    return C509Cbor.copyInts(keyAlgorithms);
  }

  static C509PreferredSignatureAlgorithm read(CborDecoder in) throws CodecException {
    int sigAlg = in.readInt();
    CborType type = in.peekType();
    if (type.isNull()) {
      in.readNull();
      return new C509PreferredSignatureAlgorithm(sigAlg);
    }
    if (type.isInt()) {
      return new C509PreferredSignatureAlgorithm(sigAlg, in.readInt());
    }

    // [ 2* IntAlgorithmIdentifier ]: a single algorithm is encoded as an integer
    int[] keyAlgs = in.readInts();
    if (keyAlgs.length < 2) {
      throw new CodecException("pubKeyAlgIdentifiers: array of " + keyAlgs.length
          + " algorithms, at least 2 are required");
    }
    return new C509PreferredSignatureAlgorithm(sigAlg, keyAlgs);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeInt(signatureAlgorithm);
    if (keyAlgorithms == null) {
      out.writeNull();
    } else if (keyAlgorithms.length == 1) {
      out.writeInt(keyAlgorithms[0]);
    } else {
      out.writeInts(keyAlgorithms);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    C509TextTree sub = out.nest(ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm));
    if (keyAlgorithms != null) {
      for (int k : keyAlgorithms) {
        sub.line("key: " + ConstRegistry.PUBLIC_KEY_ALGORITHM.describe(k));
      }
    }
  }

}
