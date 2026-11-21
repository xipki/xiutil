// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.sign.C509Signed;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * C509BasicOCSPResponse: answers for several certificates of several issuers.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509BasicOCSPResponse extends C509Signed<C509TBSBasicOCSPResponse>
    implements C509OCSPResponse {

  public C509BasicOCSPResponse(C509TBSBasicOCSPResponse body, SignatureValue signature) {
    super(body, signature);
  }

  @Override
  public Kind kind() {
    return Kind.BASIC;
  }

  @Override
  public int hashAlgorithm() {
    return body().hashAlgorithm();
  }

  @Override
  public byte[] nonce() {
    return body().nonce();
  }

  @Override
  public C509HashedId responderHash() {
    return body().responderHash();
  }

  @Override
  public Instant producedAt() {
    return body().producedAt();
  }

  @Override
  public C509Extensions extensions() {
    return body().extensions();
  }

  public List<C509PerIssuerOCSPResponse> responses() {
    return body().responses();
  }

  @Override
  public Map<C509HashedId, C509CertStatusInfos> getCertStatuses() {
    return body().getCertStatuses();
  }

  @Override
  public C509CertChainVariant responderCerts() {
    return body().responderCerts();
  }

  static C509BasicOCSPResponse readRest(CborDecoder in, int length) throws CodecException {
    C509OCSPResponse.checkLength(Kind.BASIC, length, 10);
    C509TBSBasicOCSPResponse body = C509TBSBasicOCSPResponse.readRest(in);
    return new C509BasicOCSPResponse(body, readSignature(in, body));
  }

}
