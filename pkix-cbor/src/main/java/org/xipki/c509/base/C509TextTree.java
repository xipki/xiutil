// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.util.Collection;

/**
 * Indented, line-oriented text writer used by {@link C509CborItem#render(TextTree)}.
 * Lines are separated by a newline, the output never ends with one.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TextTree {

  private final StringBuilder out;

  private final int depth;

  private final int origin;

  private C509TextTree(StringBuilder out, int depth, int origin) {
    this.out = out;
    this.depth = depth;
    this.origin = origin;
  }

  public static C509TextTree into(StringBuilder out, int depth) {
    return new C509TextTree(out, depth, out.length());
  }

  public static String asText(C509CborItem item) {
    StringBuilder sb = new StringBuilder();
    item.render(into(sb, 0));
    return sb.toString();
  }

  private void startLine() {
    if (out.length() > origin && out.charAt(out.length() - 1) != '\n') {
      out.append('\n');
    }
  }

  public C509TextTree line(String text) {
    startLine();
    ToStringUtil.appendIndent(out, depth, text);
    return this;
  }

  public C509TextTree kv(String key, Object value) {
    return line(key + ": " + (value == null ? "-" : value));
  }

  public C509TextTree lines(Collection<?> values) {
    for (Object v : values) {
      line(String.valueOf(v));
    }
    return this;
  }

  /**
   * Writes a heading and returns a writer one level deeper.
   */
  public C509TextTree nest(String heading) {
    line(heading);
    return new C509TextTree(out, depth + 1, origin);
  }

  /**
   * Writes the item at the current level.
   */
  public C509TextTree inline(C509CborItem item) {
    item.render(this);
    return this;
  }

  public C509TextTree item(String heading, C509CborItem value) {
    if (value == null) {
      return kv(heading, null);
    }
    value.render(nest(heading));
    return this;
  }

  public C509TextTree items(String heading, Collection<? extends C509CborItem> values) {
    C509TextTree sub = nest(heading + " (" + values.size() + ")");
    int i = 0;
    for (C509CborItem v : values) {
      sub.item("#" + (i++), v);
    }
    return this;
  }

  /**
   * Writes a value of the codec library, which brings its own text form.
   */
  public C509TextTree external(String heading, CborEncodable value) {
    if (value == null) {
      return kv(heading, null);
    }
    nest(heading);
    startLine();
    value.toString(out, depth + 1);
    return this;
  }

  public C509TextTree hex(String heading, byte[] value) {
    if (value == null) {
      return kv(heading, null);
    }
    nest(heading);
    startLine();
    ToStringUtil.appendHex(out, depth + 1, value);
    return this;
  }

  public C509TextTree number(String heading, BigInteger value) {
    nest(heading);
    startLine();
    ToStringUtil.appendBigInt(out, depth + 1, value);
    return this;
  }

}
