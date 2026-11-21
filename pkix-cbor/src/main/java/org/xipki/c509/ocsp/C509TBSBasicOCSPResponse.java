// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.c509.sign.C509SignedBody;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TBSBasicOCSPResponse (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * TBSBasicOCSPResponse = (
 *   ocspResponseType   : 1, ; int16
 *   signatureAlgorithm : IntAlgorithmIdentifier,
 *   hashAlgorithm      : IntAlgorithmIdentifier,
 *   nonce              : bytes .size (16..128) / null,
 *   producedAt         : ~time,
 *   extensions         : IntExtensions,
 *   responses          : PerIssuerOCSPResponses,
 *   responderCertHash  : HashedId20,
 *   responderCerts     : CertChainVariant / null,
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TBSBasicOCSPResponse extends C509SignedBody {

  private final int hashAlgorithm;

  private final byte[] nonce;

  private final C509HashedId responderHash;

  private final Instant producedAt;

  private final C509Extensions extensions;

  private final List<C509PerIssuerOCSPResponse> responses;

  private final Integer signatureAlgorithm;

  private final C509CertChainVariant responderCerts;

  public C509TBSBasicOCSPResponse(
      int signatureAlgorithm, int hashAlgorithm, byte[] nonce,
      C509HashedId responderHash, Instant producedAt, C509Extensions extensions,
      List<C509PerIssuerOCSPResponse> responses,
      C509CertChainVariant responderCerts) {
    this.signatureAlgorithm = signatureAlgorithm;
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = C509Cbor.copy(nonce);
    this.responderHash = Args.notNull(responderHash, "responderHash");
    this.producedAt = Args.notNull(producedAt, "producedAt");
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.responses = C509Cbor.nonEmpty(C509Cbor.frozen(responses, "responses"), "responses");
    this.responderCerts = responderCerts;
  }

  @Override
  public int signatureAlgorithm() {
    return signatureAlgorithm;
  }

  public int hashAlgorithm() {
    return hashAlgorithm;
  }

  public byte[] nonce() {
    return C509Cbor.copy(nonce);
  }

  public C509HashedId responderHash() {
    return responderHash;
  }

  public Instant producedAt() {
    return producedAt;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public List<C509PerIssuerOCSPResponse> responses() {
    return responses;
  }

  public Map<C509HashedId, C509CertStatusInfos> getCertStatuses() {
    Map<C509HashedId, C509CertStatusInfos> ret = new HashMap<>(responses.size());
    for (C509PerIssuerOCSPResponse response : responses) {
      ret.put(response.issuerHash(), response.getCertStatuses(producedAt));
    }
    return ret;
  }

  public C509CertChainVariant responderCerts() {
    return responderCerts;
  }

  @Override
  protected int fieldCount() {
    return 9;
  }

  static C509TBSBasicOCSPResponse readRest(CborDecoder in) throws CodecException {
    int sigAlg = in.readInt();
    int hashAlg = in.readInt();
    byte[] nonce = C509Cbor.readBytesOrNull(in);
    C509HashedId responderHash = new C509HashedId(in.readByteString());
    Instant producedAt = in.readUnwrappedInstant();
    C509Extensions extensions = C509Extensions.read(in);
    List<C509PerIssuerOCSPResponse> responses = C509PerIssuerOCSPResponse.readList(in);
    return new C509TBSBasicOCSPResponse(sigAlg, hashAlg, nonce, responderHash, producedAt,
        extensions, responses, C509Cbor.orNull(in, C509CertChainVariant::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(C509OCSPResponse.Kind.BASIC.code());
    out.writeInt(signatureAlgorithm);
    out.writeInt(hashAlgorithm);
    C509Cbor.writeBytesOrNull(out, nonce);
    out.writeByteString(responderHash.raw());
    out.writeUnwrappedTime(producedAt);
    extensions.encode(out);
    C509Cbor.writeGroups(out, C509PerIssuerOCSPResponse.WIDTH, responses);
    out.writeObject(responderCerts);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("kind", C509OCSPResponse.Kind.BASIC)
        .kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm))
        .kv("hash algorithm", ConstRegistry.HASH_ALGORITHM.describe(hashAlgorithm))
        .hex("nonce", nonce)
        .kv("responder hash", responderHash)
        .kv("produced at", producedAt)
        .item("extensions", extensions)
        .items("responses", responses)
        .item("responder certificates", responderCerts);
  }

}
