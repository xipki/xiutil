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
import org.xipki.codec.util.BigIntegers;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;

/**
 * TBSSimpleOCSPResponse (draft-liao-cose-c509-revocation-01, Section 7.5.1).
 *
 * <pre>
 * TBSSimpleOCSPResponse = (
 *   ocspResponseType   : 2, ; int16
 *   signatureAlgorithm : IntAlgorithmIdentifier,
 *   hashAlgorithm      : IntAlgorithmIdentifier,
 *   nonce              : bytes .size (16..128) / null,
 *   responderCertHash  : HashedId20,
 *   issuerCertHash     : HashedId20,
 *   serialNumber       : bytes .size (1..20),
 *   certStatus         : CertStatus,
 *   producedAt         : ~time,
 *   thisUpdate         : nint / 0,
 *   nextUpdate         : uint63 / null,
 *   extensions         : IntExtensions,
 *   responderCerts     : CertChainVariant / null,
 * )
 * </pre>
 *
 * thisUpdate and nextUpdate are seconds relative to producedAt.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TBSSimpleOCSPResponse extends C509SignedBody {

  private final int signatureAlgorithm;

  private final int hashAlgorithm;

  private final byte[] nonce;

  private final C509HashedId responderHash;

  private final Instant producedAt;

  private final C509SingleCertResponse answer;

  private final C509HashedId issuerHash;

  private final C509CertChainVariant responderCerts;

  public C509TBSSimpleOCSPResponse(
      int signatureAlgorithm, int hashAlgorithm, byte[] nonce,
      C509HashedId responderHash, C509HashedId issuerHash,
      Instant producedAt, C509SingleCertResponse answer,
      C509CertChainVariant responderCerts) {
    this.signatureAlgorithm = signatureAlgorithm;
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = C509Cbor.copy(nonce);
    this.responderHash = Args.notNull(responderHash, "responderHash");
    this.issuerHash = Args.notNull(issuerHash, "issuerHash");
    this.producedAt = Args.notNull(producedAt, "producedAt");
    this.answer = Args.notNull(answer, "answer");
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

  public C509HashedId issuerHash() {
    return issuerHash;
  }

  public Instant producedAt() {
    return producedAt;
  }

  /** Serial number hash, status, update times and extensions. */
  public C509SingleCertResponse answer() {
    return answer;
  }

  public C509CertChainVariant responderCerts() {
    return responderCerts;
  }

  public Map<C509HashedId, C509CertStatusInfos> getCertStatuses() {
    return Map.of(issuerHash, new C509CertStatusInfos(answer.getCertStatus(producedAt)));
  }

  @Override
  protected int fieldCount() {
    return 13;
  }

  static C509TBSSimpleOCSPResponse readRest(CborDecoder in) throws CodecException {
    int sigAlg = in.readInt();
    int hashAlg = in.readInt();
    byte[] nonce = C509Cbor.readBytesOrNull(in);
    C509HashedId responderHash = new C509HashedId(in.readByteString());
    C509HashedId issuerHash = new C509HashedId(in.readByteString());
    BigInteger serial = new BigInteger(1, in.readByteString());
    C509CertStatus status = C509CertStatus.read(in);
    Instant producedAt = in.readUnwrappedInstant();
    long thisUpdate = in.readLong();
    Long nextUpdate = in.readLongObj();
    C509SingleCertResponse answer = new C509SingleCertResponse(
        serial, status, thisUpdate, nextUpdate, C509Extensions.read(in));
    return new C509TBSSimpleOCSPResponse(sigAlg, hashAlg, nonce, responderHash, issuerHash,
        producedAt, answer, C509Cbor.orNull(in, C509CertChainVariant::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(C509OCSPResponse.Kind.SIMPLE.code());
    out.writeInt(signatureAlgorithm);
    out.writeInt(hashAlgorithm);
    C509Cbor.writeBytesOrNull(out, nonce);
    out.writeByteString(responderHash.raw());
    out.writeByteString(issuerHash.raw());
    out.writeByteString(BigIntegers.asUnsignedByteArray(answer.serialNumber()));
    answer.status().encode(out);
    out.writeUnwrappedTime(producedAt);
    out.writeLong(answer.thisUpdate());
    out.writeLongObj(answer.nextUpdate());
    answer.extensions().encode(out);
    out.writeObject(responderCerts);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("kind", C509OCSPResponse.Kind.SIMPLE)
        .kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm))
        .kv("hash algorithm", ConstRegistry.HASH_ALGORITHM.describe(hashAlgorithm))
        .hex("nonce", nonce)
        .kv("responder hash", responderHash)
        .kv("issuer hash", issuerHash)
        .kv("produced at", producedAt)
        .item("answer", answer)
        .item("responder certificates", responderCerts);
  }

}
