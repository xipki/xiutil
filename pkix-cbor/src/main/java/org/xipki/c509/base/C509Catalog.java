// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongFunction;

/**
 * Maps a numeric type identifier (extension ID, attribute type, ...) to the class and reader of
 * its value. Identifiers without an entry fall back to a generic reader.
 *
 * @param <V> the common base type of the values.
 * @author Lijun Liao (xipki)
 */
public final class C509Catalog<V extends C509CborItem> {

  private static final class Binding<V> {

    private final Class<? extends V> type;

    private final C509Cbor.Reader<? extends V> reader;

    /** The value standing for CBOR null, or null if CBOR null is not allowed. */
    private final V nullValue;

    private Binding(Class<? extends V> type, C509Cbor.Reader<? extends V> reader, V nullValue) {
      this.type = type;
      this.reader = reader;
      this.nullValue = nullValue;
    }

  }

  // concurrent: bindings may be added at runtime while other threads read
  private final Map<Long, Binding<V>> bindings = new ConcurrentHashMap<>();

  private final C509Cbor.Reader<? extends V> fallback;

  private final LongFunction<String> describer;

  public C509Catalog(C509Cbor.Reader<? extends V> fallback, LongFunction<String> describer) {
    this.fallback = fallback;
    this.describer = describer;
  }

  /**
   * Binds the identifiers to a value class.
   */
  public C509Catalog<V> bind(
      Class<? extends V> type, C509Cbor.Reader<? extends V> reader, long... ids) {
    return put(type, reader, null, ids);
  }

  /**
   * Like {@link #bind}, but the value may also be CBOR null, represented by {@code nullValue}.
   */
  public C509Catalog<V> bindNullable(
      Class<? extends V> type, C509Cbor.Reader<? extends V> reader,
      V nullValue, long... ids) {
    Args.notNull(nullValue, "nullValue");
    return put(type, in -> in.skipNull() ? nullValue : reader.read(in), nullValue, ids);
  }

  /**
   * Binds identifiers whose value is always CBOR null, represented by {@code nullValue}.
   */
  public C509Catalog<V> bindAlwaysNull(V nullValue, long... ids) {
    Args.notNull(nullValue, "nullValue");
    return put(null, in -> {
      in.readNull();
      return nullValue;
    }, nullValue, ids);
  }

  // synchronized: either all or none of the ids are bound
  private synchronized C509Catalog<V> put(
      Class<? extends V> type, C509Cbor.Reader<? extends V> reader, V nullValue, long... ids) {
    Args.notNull(reader, "reader");
    for (long id : ids) {
      if (bindings.containsKey(id)) {
        throw new IllegalStateException("duplicate binding for " + describer.apply(id));
      }
    }

    for (long id : ids) {
      if (bindings.putIfAbsent(id, new Binding<>(type, reader, nullValue)) != null) {
        throw new IllegalStateException("duplicate binding for " + describer.apply(id));
      }
    }
    return this;
  }

  public V read(long id, CborDecoder in) throws CodecException {
    Binding<V> b = bindings.get(id);
    return (b == null) ? fallback.read(in) : b.reader.read(in);
  }

  /**
   * Checks that the value fits the identifier. A value of a foreign class is re-read from its
   * encoding with the bound reader.
   *
   * @return the value as an instance of the bound class.
   * @throws IllegalArgumentException if the value does not fit.
   */
  public V adopt(long id, V value) {
    if (value == null) {
      throw new IllegalArgumentException("value of " + describer.apply(id) + " must not be null");
    }

    Binding<V> b = bindings.get(id);
    if (b == null) {
      return value;
    }

    if (b.nullValue != null && b.nullValue.getClass().isInstance(value)) {
      return b.nullValue;
    }

    if (b.type == null) {
      throw new IllegalArgumentException(describer.apply(id) + " does not take a value");
    }

    if (b.type.isInstance(value)) {
      return value;
    }

    try {
      return C509Cbor.parse(value.encoding(), b.reader);
    } catch (CodecException | RuntimeException e) {
      throw new IllegalArgumentException(describer.apply(id) + " does not accept "
          + value.getClass().getName(), e);
    }
  }

}
