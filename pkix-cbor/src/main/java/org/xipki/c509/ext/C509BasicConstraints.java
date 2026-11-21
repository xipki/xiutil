// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The basic constraints extension, encoded as one integer: -2 for an end entity, -1 for a CA
 * without path length constraint, otherwise the path length constraint of a CA.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509BasicConstraints extends C509ExtnValue {

  private static final int END_ENTITY_CODE = -2;

  private static final int UNLIMITED_CODE = -1;

  public static final C509BasicConstraints END_ENTITY = new C509BasicConstraints(END_ENTITY_CODE);

  public static final C509BasicConstraints UNLIMITED_CA = new C509BasicConstraints(UNLIMITED_CODE);

  private final int code;

  private C509BasicConstraints(int code) {
    if (code < END_ENTITY_CODE) {
      throw new IllegalArgumentException("invalid basic constraints code " + code);
    }
    this.code = code;
  }

  /**
   * @param pathLen the path length constraint, or null for none.
   */
  public static C509BasicConstraints ca(Integer pathLen) {
    if (pathLen == null) {
      return UNLIMITED_CA;
    }
    if (pathLen < 0) {
      throw new IllegalArgumentException("negative pathLen " + pathLen);
    }
    return new C509BasicConstraints(pathLen);
  }

  public boolean isCA() {
    return code != END_ENTITY_CODE;
  }

  /**
   * Returns the path length constraint, or null for an end entity or an unconstrained CA.
   */
  public Integer pathLen() {
    return code >= 0 ? code : null;
  }

  /**
   * Returns the value in the convention of {@code X509Certificate.getBasicConstraints()}.
   */
  public int x509Value() {
    return code == END_ENTITY_CODE ? -1 : code == UNLIMITED_CODE ? Integer.MAX_VALUE : code;
  }

  public static C509BasicConstraints read(CborDecoder in) throws CodecException {
    int code = in.readInt();
    return code == END_ENTITY_CODE ? END_ENTITY
        : code == UNLIMITED_CODE ? UNLIMITED_CA : new C509BasicConstraints(code);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(code);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(!isCA() ? "end entity"
        : "CA, path length: " + (code == UNLIMITED_CODE ? "unlimited" : code));
  }

  @Override
  public String label() {
    return "Basic Constraints";
  }

}
