// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;
import java.util.List;

/**
 * One distribution point (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * DistributionPointName = [
 *   fullName:  [ 2 * text ] / text,
 *   reasons:   uint / null,
 *   cRLIssuer: Name / null,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509DistributionPointName extends C509CborItem {

  private final List<String> uris;

  private final Integer reasons;

  private final C509Name crlIssuer;

  public C509DistributionPointName(List<String> uris, Integer reasons, C509Name crlIssuer) {
    this.uris = C509Cbor.nonEmpty(C509Cbor.frozen(uris, "uris"), "uris");
    this.reasons = reasons;
    this.crlIssuer = crlIssuer;
  }

  public static C509DistributionPointName of(String... uris) {
    return new C509DistributionPointName(Arrays.asList(uris), null, null);
  }

  public List<String> uris() {
    return uris;
  }

  /** The raw reason flags, or null. */
  public Integer reasons() {
    return reasons;
  }

  public C509ReasonFlags reasonFlags() {
    return reasons == null ? null : new C509ReasonFlags(reasons);
  }

  public C509Name crlIssuer() {
    return crlIssuer;
  }

  boolean isPlainUri() {
    return reasons == null && crlIssuer == null && uris.size() == 1;
  }

  static C509DistributionPointName read(CborDecoder in) throws CodecException {
    in.readArrayLength(3);
    List<String> uris = in.peekType().isTextString()
        ? List.of(in.readTextString()) : Arrays.asList(in.readTextStrings());
    Integer reasons = in.readIntObj();
    return new C509DistributionPointName(uris, reasons, C509Cbor.orNull(in, C509Name::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(3);
    if (uris.size() == 1) {
      out.writeTextString(uris.get(0));
    } else {
      out.writeArrayStart(uris.size());
      for (String uri : uris) {
        out.writeTextString(uri);
      }
    }
    out.writeIntObj(reasons);
    out.writeObject(crlIssuer);
  }

  @Override
  protected void render(C509TextTree out) {
    out.nest("URIs").lines(uris);
    if (reasons != null) {
      out.item("reasons", reasonFlags());
    }
    if (crlIssuer != null) {
      out.kv("CRL issuer", crlIssuer.getNameText());
    }
  }

}
