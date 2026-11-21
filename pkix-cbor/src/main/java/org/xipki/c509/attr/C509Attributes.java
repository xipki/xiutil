// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A possibly empty list of attributes, encoded as a flat array of type / value pairs.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Attributes extends C509CborItem implements Iterable<C509Attribute> {

  public static final C509Attributes EMPTY = new C509Attributes(List.of());

  private final List<C509Attribute> list;

  public C509Attributes(Collection<C509Attribute> attributes) {
    this.list = C509Cbor.frozen(attributes == null ? List.of() : attributes, "attributes");
  }

  public static C509Attributes of(C509Attribute... attributes) {
    return new C509Attributes(Arrays.asList(attributes));
  }

  public List<C509Attribute> asList() {
    return list;
  }

  public int size() {
    return list.size();
  }

  @Override
  public Iterator<C509Attribute> iterator() {
    return list.iterator();
  }

  public List<C509Attribute> all(long type) {
    return list.stream().filter(a -> a.type() == type).collect(Collectors.toList());
  }

  public C509Attribute first(long type) {
    return list.stream().filter(a -> a.type() == type).findFirst().orElse(null);
  }

  public <T extends C509AttrValue> T firstValue(long type, Class<T> clazz) {
    C509Attribute a = first(type);
    return a == null ? null : a.value(clazz);
  }

  public static C509Attributes read(CborDecoder in) throws CodecException {
    return new C509Attributes(C509Cbor.readGroups(in, 2, "Attributes", C509Attribute::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, list);
  }

  @Override
  protected void render(C509TextTree out) {
    if (list.isEmpty()) {
      out.line("<none>");
    }
    list.forEach(out::inline);
  }

}
