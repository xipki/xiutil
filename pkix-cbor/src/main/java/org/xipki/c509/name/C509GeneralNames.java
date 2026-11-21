// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Iterator;
import java.util.List;

/**
 * A non-empty sequence of general names, encoded as one flat array of tag / value pairs.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509GeneralNames extends C509CborItem implements Iterable<C509GeneralName> {

  private final List<C509GeneralName> names;

  public C509GeneralNames(List<C509GeneralName> names) {
    this.names = C509Cbor.nonEmpty(C509Cbor.frozen(names, "names"), "names");
  }

  public static C509GeneralNames of(C509GeneralName... names) {
    return new C509GeneralNames(List.of(names));
  }

  public List<C509GeneralName> asList() {
    return names;
  }

  public int size() {
    return names.size();
  }

  public C509GeneralName first() {
    return names.get(0);
  }

  @Override
  public Iterator<C509GeneralName> iterator() {
    return names.iterator();
  }

  public static C509GeneralNames read(CborDecoder in) throws CodecException {
    return new C509GeneralNames(C509Cbor.readGroups(in, 2, "GeneralNames", C509GeneralName::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, names);
  }

  @Override
  protected void render(C509TextTree out) {
    for (C509GeneralName n : names) {
      out.inline(n);
    }
  }

}
