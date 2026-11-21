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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * PerIssuerOCSPResponse (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * PerIssuerOCSPResponse = (
 *   issuerCertHash   : HashedId20,
 *   extensions       : IntExtensions,
 *   singleResponses  : SingleCertResponses,
 * )
 * SingleCertResponses = [ + SingleCertResponse ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerOCSPResponse extends C509CborItem {

  static final int WIDTH = 3;

  private final C509HashedId issuerHash;

  private final C509Extensions extensions;

  private final List<C509SingleCertResponse> answers;

  public C509PerIssuerOCSPResponse(
      C509HashedId issuerHash, C509Extensions extensions,
      List<C509SingleCertResponse> answers) {
    this.issuerHash = Args.notNull(issuerHash, "issuerHash");
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.answers = C509Cbor.nonEmpty(C509Cbor.frozen(answers, "answers"), "answers");
  }

  public C509HashedId issuerHash() {
    return issuerHash;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public List<C509SingleCertResponse> answers() {
    return answers;
  }

  public C509CertStatusInfos getCertStatuses(Instant producedAt) {
    List<C509CertStatusInfo> ret = new ArrayList<>(answers.size());
    for (C509SingleCertResponse answer : answers) {
      ret.add(answer.getCertStatus(producedAt));
    }
    return new C509CertStatusInfos(ret);
  }

  static C509PerIssuerOCSPResponse read(CborDecoder in) throws CodecException {
    C509HashedId issuerHash = new C509HashedId(in.readByteString());
    C509Extensions extensions = C509Extensions.read(in);
    return new C509PerIssuerOCSPResponse(issuerHash, extensions,
        C509Cbor.readGroups(in, C509SingleCertResponse.WIDTH, "SingleCertResponses",
            C509SingleCertResponse::read));
  }

  static List<C509PerIssuerOCSPResponse> readList(CborDecoder in) throws CodecException {
    return C509Cbor.nonEmpty(C509Cbor.readGroups(in, WIDTH, "PerIssuerOCSPResponses",
        C509PerIssuerOCSPResponse::read), "responses");
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(issuerHash.raw());
    extensions.encode(out);
    C509Cbor.writeGroups(out, C509SingleCertResponse.WIDTH, answers);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("issuer hash", issuerHash).item("extensions", extensions).items("answers", answers);
  }

}
