// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.sign.C509Signed;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;
import java.util.Map;

/**
 * C509SimpleOCSPResponse: the answer for exactly one certificate.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SimpleOCSPResponse extends C509Signed<C509TBSSimpleOCSPResponse>
    implements C509OCSPResponse {

  public C509SimpleOCSPResponse(C509TBSSimpleOCSPResponse body, SignatureValue signature) {
    super(body, signature);
  }

  @Override
  public Kind kind() {
    return Kind.SIMPLE;
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

  public C509HashedId issuerHash() {
    return body().issuerHash();
  }

  @Override
  public Instant producedAt() {
    return body().producedAt();
  }

  @Override
  public C509Extensions extensions() {
    return answer().extensions();
  }

  /** Serial number hash, status, update times and extensions. */
  public C509SingleCertResponse answer() {
    return body().answer();
  }

  @Override
  public C509CertChainVariant responderCerts() {
    return body().responderCerts();
  }

  @Override
  public Map<C509HashedId, C509CertStatusInfos> getCertStatuses() {
    return body().getCertStatuses();
  }

  static C509SimpleOCSPResponse readRest(CborDecoder in, int length) throws CodecException {
    C509OCSPResponse.checkLength(Kind.SIMPLE, length, 14);
    C509TBSSimpleOCSPResponse body = C509TBSSimpleOCSPResponse.readRest(in);
    return new C509SimpleOCSPResponse(body, readSignature(in, body));
  }

}
