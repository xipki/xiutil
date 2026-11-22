// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

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

  /**
   * Registers the value class of extension IDs not known to this library, so that they are
   * decoded into {@code clazz} instead of {@link C509RawExtnValue}. Register before the first
   * extension with these IDs is decoded or created, e.g. at application start-up. To give the
   * IDs a name, use {@link ConstExtensionId#register(long, String)}.
   *
   * @param <T>    the value class.
   * @param clazz  the value class.
   * @param reader reads the value from the CBOR stream, usually {@code MyValue::read}.
   * @param ids    the extension IDs.
   * @throws IllegalStateException if one of the IDs is already registered; then none of the
   *         IDs is registered.
   */
  public static <T extends C509ExtnValue> void register(
      Class<T> clazz, C509Cbor.Reader<T> reader, long... ids) {
    Args.notNull(clazz, "clazz");
    Args.notNull(reader, "reader");
    C509ExtnCatalog.INSTANCE.bind(clazz, reader, checkIds(ids));
  }

  /**
   * Like {@link #register}, but the value may also be CBOR null, represented by
   * {@link C509NullExtnValue#INSTANCE}.
   */
  public static <T extends C509ExtnValue> void registerNullable(
      Class<T> clazz, C509Cbor.Reader<T> reader, long... ids) {
    Args.notNull(clazz, "clazz");
    Args.notNull(reader, "reader");
    C509ExtnCatalog.INSTANCE.bindNullable(clazz, reader, C509NullExtnValue.INSTANCE,
        checkIds(ids));
  }

  /**
   * Registers extension IDs whose value is always CBOR null, represented by
   * {@link C509NullExtnValue#INSTANCE}, like OCSP no-check.
   *
   * @param ids the extension IDs.
   * @throws IllegalStateException if one of the IDs is already registered; then none of the
   *         IDs is registered.
   */
  public static void registerAlwaysNull(long... ids) {
    C509ExtnCatalog.INSTANCE.bindAlwaysNull(C509NullExtnValue.INSTANCE, checkIds(ids));
  }

  private static long[] checkIds(long[] ids) {
    if (ids == null || ids.length == 0) {
      throw new IllegalArgumentException("ids must not be empty");
    }

    for (long id : ids) {
      if (id <= 0) {
        throw new IllegalArgumentException("extension ID must be positive: " + id);
      }
    }
    return ids;
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
    long signedId = in.readLong();
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
