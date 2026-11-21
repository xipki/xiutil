// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The name constraints extension (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * GeneralSubtrees = [ + GeneralName ]
 * NameConstraints = [
 *   permittedSubtrees: GeneralSubtrees / null,
 *   excludedSubtrees: GeneralSubtrees / null,
 * ]
 * </pre>
 *
 * IP address subtrees carry the address followed by one byte with the prefix length.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509NameConstraints extends C509ExtnValue {

  private final C509GeneralNames permitted;

  private final C509GeneralNames excluded;

  public C509NameConstraints(C509GeneralNames permitted, C509GeneralNames excluded) {
    this.permitted = checkSubtrees(permitted, "permitted");
    this.excluded = checkSubtrees(excluded, "excluded");
  }

  private static C509GeneralNames checkSubtrees(C509GeneralNames subtrees, String what) {
    if (subtrees == null) {
      return null;
    }
    for (C509GeneralName n : subtrees) {
      if (n.tag() != ConstGeneralNameTag.iPAddress) {
        continue;
      }
      byte[] b = n.octets();
      if (b.length != 5 && b.length != 17) {
        throw new IllegalArgumentException(what
            + ": only IPv4 and IPv6 subnets (address and prefix length) are supported");
      }
      int prefixLen = b[b.length - 1] & 0xFF;
      if (prefixLen == 0 || prefixLen > 8 * (b.length - 1)) {
        throw new IllegalArgumentException(what + ": invalid prefix length " + prefixLen);
      }
    }
    return subtrees;
  }

  public C509GeneralNames permitted() {
    return permitted;
  }

  public C509GeneralNames excluded() {
    return excluded;
  }

  public static C509NameConstraints read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    C509GeneralNames permitted = C509Cbor.orNull(in, C509GeneralNames::read);
    return new C509NameConstraints(permitted, C509Cbor.orNull(in, C509GeneralNames::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    out.writeObject(permitted);
    out.writeObject(excluded);
  }

  @Override
  protected void render(C509TextTree out) {
    out.item("permitted", permitted).item("excluded", excluded);
  }

  @Override
  public String label() {
    return "Name Constraints";
  }

}
