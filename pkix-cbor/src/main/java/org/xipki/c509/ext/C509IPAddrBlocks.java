// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ipres.C509IPAddressFamily;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.List;

/**
 * The IP address blocks extension: the address families in canonical order, each contributing
 * three elements to one flat array.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509IPAddrBlocks extends C509ExtnValue {

  private final List<C509IPAddressFamily> families;

  public C509IPAddrBlocks(List<C509IPAddressFamily> families) {
    List<C509IPAddressFamily> sorted = new ArrayList<>(C509Cbor.frozen(families, "families"));
    sorted.sort(C509IPAddressFamily.ORDER);
    this.families = C509Cbor.nonEmpty(List.copyOf(sorted), "families");
  }

  public static C509IPAddrBlocks of(C509IPAddressFamily... families) {
    return new C509IPAddrBlocks(List.of(families));
  }

  public List<C509IPAddressFamily> families() {
    return families;
  }

  public static C509IPAddrBlocks read(CborDecoder in) throws CodecException {
    return new C509IPAddrBlocks(
        C509Cbor.readGroups(in, 3, "IPAddrBlocks", C509IPAddressFamily::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 3, families);
  }

  @Override
  protected void render(C509TextTree out) {
    for (C509IPAddressFamily f : families) {
      out.item("family", f);
    }
  }

  @Override
  public String label() {
    return "IP Address Blocks";
  }

}
