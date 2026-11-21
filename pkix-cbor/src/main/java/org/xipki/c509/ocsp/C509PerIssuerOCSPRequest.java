// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.List;

/**
 * PerIssuerOCSPRequest (draft-liao-cose-c509-revocation-01, Section 7.4.1).
 *
 * <pre>
 * PerIssuerOCSPRequest = (
 *   issuerCertHash   : HashedId20,
 *   extensions       : IntExtensions,
 *   singleRequests   : SingleCertRequests,
 * )
 * SingleCertRequests  = [ + SingleCertRequest ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerOCSPRequest extends C509CborItem {

  static final int WIDTH = 3;

  private final C509HashedId issuerHash;

  private final C509Extensions extensions;

  private final List<C509SingleCertRequest> queries;

  public C509PerIssuerOCSPRequest(
      C509HashedId issuerHash, C509Extensions extensions,
      List<C509SingleCertRequest> queries) {
    this.issuerHash = Args.notNull(issuerHash, "issuerHash");
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.queries = C509Cbor.nonEmpty(C509Cbor.frozen(queries, "queries"), "queries");
  }

  public C509HashedId issuerHash() {
    return issuerHash;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public List<C509SingleCertRequest> queries() {
    return queries;
  }

  static C509PerIssuerOCSPRequest read(CborDecoder in) throws CodecException {
    C509HashedId issuerHash = new C509HashedId(in.readByteString());
    C509Extensions extensions = C509Extensions.read(in);
    return new C509PerIssuerOCSPRequest(issuerHash, extensions,
        C509Cbor.readGroups(in, C509SingleCertRequest.WIDTH, "SingleCertRequests",
            C509SingleCertRequest::read));
  }

  static List<C509PerIssuerOCSPRequest> readList(CborDecoder in) throws CodecException {
    return C509Cbor.nonEmpty(C509Cbor.readGroups(in, WIDTH, "PerIssuerOCSPRequests",
        C509PerIssuerOCSPRequest::read), "requests");
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(issuerHash.raw());
    extensions.encode(out);
    C509Cbor.writeGroups(out, C509SingleCertRequest.WIDTH, queries);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("issuer hash", issuerHash).item("extensions", extensions).items("queries", queries);
  }

}
