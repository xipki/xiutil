// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;

/**
 * Root of all immutable C509 values in this module.
 * <p>
 * Every value has exactly one CBOR form. Equality and hash code are therefore defined on the
 * encoded bytes, which are computed once and cached. Human-readable output goes through
 * {@link #render(C509TextTree)}}.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509CborItem extends CborEncodable {

  private volatile byte[] cachedEncoding;

  /**
   * Writes this value to the encoder.
   *
   * @param out the target encoder.
   * @throws CodecException if the value could not be encoded.
   */
  protected abstract void writeTo(CborEncoder out) throws CodecException;

  /**
   * Appends a textual description of this value.
   *
   * @param out the text sink.
   */
  protected abstract void render(C509TextTree out);

  @Override
  public final void encode(CborEncoder encoder) throws CodecException {
    writeTo(encoder);
  }

  @Override
  public final StringBuilder toString(StringBuilder buf, int indentLevel) {
    render(C509TextTree.into(buf, indentLevel));
    return buf;
  }

  @Override
  public byte[] getEncoded() {
    return encoding().clone();
  }

  /**
   * Returns the cached encoding. The returned array must not be modified.
   */
  protected final byte[] encoding() {
    byte[] bytes = cachedEncoding;
    if (bytes == null) {
      bytes = super.getEncoded();
      cachedEncoding = bytes;
    }
    return bytes;
  }

  private byte[] encodingOrFail() {
    return encoding();
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (other == null || other.getClass() != getClass()) {
      return false;
    }
    return Arrays.equals(encodingOrFail(), ((C509CborItem) other).encodingOrFail());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encodingOrFail());
  }

}
