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
import java.util.stream.Collectors;

/**
 * The subject template (draft-ietf-cose-cbor-encoded-cert-21, Section 4.4).
 *
 * <pre>
 * NameTemplate = [ * RDNAttributeTemplate ]
 *
 * RDNAttributeTemplate = (
 *   ( attributeType: uint, minOccurs: uint, maxOccurs: uint,
 *     attributeValue: SpecialText / undefined ) //
 *   ( attributeType: ~oid, minOccurs: uint, maxOccurs: uint,
 *     attributeValue: bytes / undefined )
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509NameTemplate extends C509CborItem {

  private final List<C509RDNAttributeTemplate> attributes;

  public C509NameTemplate(List<C509RDNAttributeTemplate> attributes) {
    this.attributes = C509Cbor.frozen(attributes, "attributes");
  }

  public static C509NameTemplate of(C509RDNAttributeTemplate... attributes) {
    return new C509NameTemplate(Arrays.asList(attributes));
  }

  public List<C509RDNAttributeTemplate> attributes() {
    return attributes;
  }

  static C509NameTemplate read(CborDecoder in) throws CodecException {
    return new C509NameTemplate(
        C509Cbor.readGroups(in, 4, "NameTemplate", C509RDNAttributeTemplate::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 4, attributes);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(attributes.isEmpty() ? "<empty>"
        : attributes.stream().map(C509RDNAttributeTemplate::text)
            .collect(Collectors.joining(", ")));
  }

}
