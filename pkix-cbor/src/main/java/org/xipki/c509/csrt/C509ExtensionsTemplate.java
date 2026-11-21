// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csrt;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;
import java.util.List;

/**
 * The extensions template (draft-ietf-cose-cbor-encoded-cert-21, Section 4.4).
 *
 * <pre>
 * ExtensionsTemplate = [ * ExtensionTemplate ]
 *
 * ExtensionTemplate = (
 *   ( extensionID: uint, optional: bool, extensionValue: any ) //
 *   ( extensionID: ~oid, optional: bool,
 *     extensionValue: bytes / undefined )
 * )
 * </pre>
 *
 * An undefined value is chosen by the requester.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ExtensionsTemplate extends C509CborItem {

  private final List<C509ExtensionTemplate> entries;

  public C509ExtensionsTemplate(List<C509ExtensionTemplate> entries) {
    this.entries = C509Cbor.frozen(entries, "entries");
  }

  public static C509ExtensionsTemplate of(C509ExtensionTemplate... entries) {
    return new C509ExtensionsTemplate(Arrays.asList(entries));
  }

  public List<C509ExtensionTemplate> entries() {
    return entries;
  }

  static C509ExtensionsTemplate read(CborDecoder in) throws CodecException {
    return new C509ExtensionsTemplate(
        C509Cbor.readGroups(in, 3, "ExtensionsTemplate", C509ExtensionTemplate::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 3, entries);
  }

  @Override
  protected void render(C509TextTree out) {
    entries.forEach(out::inline);
  }

}
