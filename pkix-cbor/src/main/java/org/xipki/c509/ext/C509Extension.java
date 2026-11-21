// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * One extension (draft-ietf-cose-cbor-encoded-cert-21, Section 3.1.10). Only the integer
 * extension IDs are supported: the absolute value is the extension ID, a negative value marks
 * a critical extension.
 *
 * <pre>
 * Extension = (
 *   ( extensionID: int, extensionValue: Defined ) //
 *   ( extensionID: ~oid, extensionValue: bytes / [ bytes ] )
 * )
 * </pre>
 *
 * The value is {@link C509NullExtnValue} for extensions without content, e.g. OCSP no-check.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Extension extends C509CborItem implements Comparable<C509Extension> {

  private final long id;

  private final boolean critical;

  private final C509ExtnValue value;

  /**
   * @param id       the extension ID, see {@link ConstExtensionId}.
   * @param critical whether the extension is critical.
   * @param value    the value, {@link C509NullExtnValue#INSTANCE} for CBOR null. A value of a
   *                 foreign class is converted to the class bound to the ID, provided its
   *                 encoding fits.
   */
  public C509Extension(long id, boolean critical, C509ExtnValue value) {
    if (id <= 0) {
      throw new IllegalArgumentException("extension ID must be positive: " + id);
    }
    this.id = id;
    this.critical = critical;
    this.value = C509ExtnCatalog.INSTANCE.adopt(id, value);
  }

  public static C509Extension critical(long id, C509ExtnValue value) {
    return new C509Extension(id, true, value);
  }

  public static C509Extension nonCritical(long id, C509ExtnValue value) {
    return new C509Extension(id, false, value);
  }

  public long id() {
    return id;
  }

  public boolean isCritical() {
    return critical;
  }

  public C509ExtnValue value() {
    return value;
  }

  public <T extends C509ExtnValue> T value(Class<T> type) {
    return type.cast(value);
  }

  /**
   * Reads the value of the given extension ID.
   */
  public static C509ExtnValue readValue(long id, CborDecoder in) throws CodecException {
    return C509ExtnCatalog.INSTANCE.read(id, in);
  }

  /**
   * Checks (and converts) a value for the given extension ID, see the constructor.
   */
  public static C509ExtnValue checkValue(long id, C509ExtnValue value) {
    return C509ExtnCatalog.INSTANCE.adopt(id, value);
  }

  public static C509Extension read(CborDecoder in) throws CodecException {
    long signedId = in.readInt();
    long id = Math.abs(signedId);
    return new C509Extension(id, signedId < 0, C509ExtnCatalog.INSTANCE.read(id, in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(critical ? -id : id);
    value.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    String heading = ConstExtensionId.describe(id) + (critical ? " [critical]" : "");
    if (value instanceof C509NullExtnValue) {
      out.line(heading);
    } else {
      out.item(heading, value);
    }
  }

  @Override
  public int compareTo(C509Extension other) {
    return Long.compare(id, other.id);
  }

}
