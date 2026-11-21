// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

/**
 * C509ErrorOCSPResponse (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * C509ErrorOCSPResponse = [
 *   ocspResponseType  : 0,  ; int16
 *   responseStatus    : -128..127
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ErrorOCSPResponse extends C509CborItem implements C509OCSPResponse {

  private final C509ResponseStatus status;

  public C509ErrorOCSPResponse(C509ResponseStatus status) {
    this.status = Args.notNull(status, "status");
  }

  @Override
  public Kind kind() {
    return Kind.ERROR;
  }

  @Override
  public int hashAlgorithm() {
    throw new IllegalStateException("hashAlgorithm() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public int signatureAlgorithm() {
    throw new IllegalStateException("signatureAlgorithm() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public SignatureValue signature() {
    throw new IllegalStateException("signature() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public byte[] nonce() {
    throw new IllegalStateException("nonce() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public C509HashedId responderHash() {
    throw new IllegalStateException("responderHash() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public Instant producedAt() {
    throw new IllegalStateException("producedAt() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public C509CertChainVariant responderCerts() {
    throw new IllegalStateException("responderCerts() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public Map<C509HashedId, C509CertStatusInfos> getCertStatuses() {
    throw new IllegalStateException("getCertStatuses() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public boolean verify(ContentVerifierFactory factory) throws SignatureException {
    throw new IllegalStateException("verify() unsupported in C509ErrorOCSPResponse");
  }

  @Override
  public C509Extensions extensions() {
    throw new IllegalStateException("extensions() unsupported in C509ErrorOCSPResponse");
  }

  public C509ResponseStatus status() {
    return status;
  }

  static C509ErrorOCSPResponse readRest(CborDecoder in, int length) throws CodecException {
    C509OCSPResponse.checkLength(Kind.ERROR, length, 2);
    try {
      return new C509ErrorOCSPResponse(C509ResponseStatus.ofCode(in.readInt()));
    } catch (IllegalArgumentException e) {
      throw new CodecException(e.getMessage(), e);
    }
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    out.writeLong(Kind.ERROR.code());
    out.writeLong(status.code());
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("kind", kind()).kv("status", status + " (" + status.code() + ")");
  }

}
