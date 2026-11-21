// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The authority / subject information access extension
 * (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * AccessDescription = ( accessMethod: int / ~oid , uri: text )
 * AuthorityInfoAccessSyntax = [ + AccessDescription ]
 * SubjectInfoAccessSyntax = AuthorityInfoAccessSyntax
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509InfoAccess extends C509ExtnValue {

  private final List<C509AccessDescription> entries;

  public C509InfoAccess(List<C509AccessDescription> entries) {
    this.entries = C509Cbor.nonEmpty(C509Cbor.frozen(entries, "entries"), "entries");
  }

  public static C509InfoAccess of(C509AccessDescription... entries) {
    return new C509InfoAccess(List.of(entries));
  }

  public List<C509AccessDescription> entries() {
    return entries;
  }

  public static C509InfoAccess read(CborDecoder in) throws CodecException {
    return new C509InfoAccess(
        C509Cbor.readGroups(in, 2, "InfoAccess", C509AccessDescription::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, entries);
  }

  @Override
  protected void render(C509TextTree out) {
    entries.forEach(out::inline);
  }

  @Override
  public String label() {
    return "Information Access";
  }

}
