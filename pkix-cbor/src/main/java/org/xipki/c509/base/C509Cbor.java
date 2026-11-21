// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Static helpers shared by the readers and writers of this module.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Cbor {

  /**
   * Reads one value from a decoder.
   *
   * @param <T> the value type.
   */
  @FunctionalInterface
  public interface Reader<T> {
    T read(CborDecoder in) throws CodecException;
  }

  private C509Cbor() {
  }

  public static <T> T parse(byte[] data, Reader<T> reader) throws CodecException {
    try (CborDecoder in = new ByteArrayCborDecoder(data)) {
      return reader.read(in);
    }
  }

  /**
   * Reads a flat array whose items come in groups of {@code width} elements.
   */
  public static <T> List<T> readGroups(CborDecoder in, int width, String what, Reader<T> reader)
      throws CodecException {
    int len = in.readArrayLength();
    if (len % width != 0) {
      throw new CodecException(what + ": array length " + len + " is not a multiple of "
          + width);
    }
    List<T> list = new ArrayList<>(len / width);
    for (int i = 0; i < len / width; i++) {
      list.add(reader.read(in));
    }
    return list;
  }

  public static <T> List<T> readArray(CborDecoder in, Reader<T> reader) throws CodecException {
    return readGroups(in, 1, "array", reader);
  }

  /**
   * Writes the items as one flat array, each item contributes {@code width} elements.
   */
  public static void writeGroups(
      CborEncoder out, int width, Collection<? extends CborEncodable> items)
      throws CodecException {
    out.writeArrayStart(items.size() * width);
    for (CborEncodable item : items) {
      item.encode(out);
    }
  }

  public static <T> T orNull(CborDecoder in, Reader<T> reader) throws CodecException {
    return in.skipNull() ? null : reader.read(in);
  }

  public static <T> T orUndefined(CborDecoder in, Reader<T> reader) throws CodecException {
    if (in.peekType().isUndefined()) {
      in.readUndefined();
      return null;
    }
    return reader.read(in);
  }

  public static void writeOrUndefined(CborEncoder out, CborEncodable value)
      throws CodecException {
    if (value == null) {
      out.writeUndefined();
    } else {
      value.encode(out);
    }
  }

  public static byte[] readBytesOrNull(CborDecoder in) throws CodecException {
    return orNull(in, CborDecoder::readByteString);
  }

  public static void writeBytesOrNull(CborEncoder out, byte[] value) throws CodecException {
    if (value == null) {
      out.writeNull();
    } else {
      out.writeByteString(value);
    }
  }

  public static int[] readIntArray(CborDecoder in) throws CodecException {
    int len = in.readArrayLength();
    int[] values = new int[len];
    for (int i = 0; i < len; i++) {
      values[i] = in.readInt();
    }
    return values;
  }

  public static void writeIntArray(CborEncoder out, int[] values) throws CodecException {
    out.writeArrayStart(values.length);
    for (int v : values) {
      out.writeInt(v);
    }
  }

  /**
   * Returns an unmodifiable, null-free copy.
   */
  public static <T> List<T> frozen(Collection<? extends T> values, String name) {
    Args.notNull(values, name);
    List<T> copy = new ArrayList<>(values.size());
    for (T v : values) {
      copy.add(Args.notNull(v, name + " element"));
    }
    return Collections.unmodifiableList(copy);
  }

  @SafeVarargs
  public static <T> List<T> frozen(String name, T... values) {
    return frozen(Arrays.asList(Args.notNull(values, name)), name);
  }

  public static <T> List<T> nonEmpty(List<T> values, String name) {
    if (values.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be empty");
    }
    return values;
  }

  public static byte[] copy(byte[] value) {
    return value == null ? null : value.clone();
  }

  public static int[] copyInts(int[] value) {
    return value == null ? null : value.clone();
  }

  public static byte[] emptyToNull(byte[] value) {
    return (value == null || value.length == 0) ? null : value.clone();
  }

}
