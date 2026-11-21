// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.ByteArrayCborEncoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.crypto.EmbedCertsMode;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.InsertionOrderedMap;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.List;

/**
 * <pre>
 * C509BasicOCSPRequest = [
 *   ocspRequestType    : 1, ; int16
 *   signatureAlgorithm : IntAlgorithmIdentifier / null, -- null if unsigned
 *   hashAlgorithm      : IntAlgorithmIdentifier,
 *   nonce              : bytes .size (16..128) / null,
 *   extensions         : IntExtensions,
 *   requests           : PerIssuerOCSPRequests
 *  ? ( -- Not present if unsigned
 *     requestorCertHash  : HashedId20 ,
 *     requestorCerts     : CertChainVariant / null,
 *     signatureValue     : any
 *   )
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509BasicOCSPRequest extends C509CborItem implements C509OCSPRequest {

  private final Integer signatureAlgorithm;

  private final int hashAlgorithm;

  private final byte[] nonce;

  private final C509HashedId requestorHash;

  private final C509Extensions extensions;

  private final List<C509PerIssuerOCSPRequest> requests;

  private final C509CertChainVariant requestorCerts;

  private final SignatureValue signatureValue;

  public C509BasicOCSPRequest(
      int hashAlgorithm, byte[] nonce, C509Extensions extensions,
      List<C509PerIssuerOCSPRequest> requests) {
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = C509Cbor.copy(nonce);
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.requests = C509Cbor.nonEmpty(C509Cbor.frozen(requests, "requests"), "requests");
    this.signatureAlgorithm = null;
    this.requestorHash = null;
    this.requestorCerts = null;
    this.signatureValue = null;
  }

  public C509BasicOCSPRequest(
      int hashAlgorithm, byte[] nonce, C509Extensions extensions,
      List<C509PerIssuerOCSPRequest> requests,
      int signatureAlgorithm, C509HashedId requestorHash,
      C509CertChainVariant requestorCerts, SignatureValue signatureValue) {
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = C509Cbor.copy(nonce);
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.requests = C509Cbor.nonEmpty(C509Cbor.frozen(requests, "requests"), "requests");
    this.signatureAlgorithm = signatureAlgorithm;
    this.requestorHash = Args.notNull(requestorHash, "requestorHash");
    this.requestorCerts = requestorCerts;
    this.signatureValue = Args.notNull(signatureValue, "signatureValue");
  }

  public C509BasicOCSPRequest(
      C509Hasher hasher, byte[] nonce, C509Extensions extensions,
      List<C509PerIssuerOCSPRequest> requests,
      C509ExtendedSigner signer, EmbedCertsMode embedCertsMode) throws SignatureException {
    CoseC509 certs = signer.certificates();
    this.hashAlgorithm = hasher.algorithm();
    this.nonce = C509Cbor.copy(nonce);
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
    this.requests = C509Cbor.nonEmpty(C509Cbor.frozen(requests, "requests"), "requests");
    this.signatureAlgorithm = signer.c509Algorithm();
    this.requestorHash = hasher.hashedIdForCert(certs.first());
    this.requestorCerts = C509CertChainVariant.select(embedCertsMode, certs);

    byte[] tbs = getEncodedTbs();
    this.signatureValue = signer.c509Sign(tbs);
  }

  @Override
  public Kind kind() {
    return Kind.BASIC;
  }

  @Override
  public int hashAlgorithm() {
    return hashAlgorithm;
  }

  /** The signature algorithm, or null if the request is unsigned. */
  public Integer signatureAlgorithm() {
    return signatureAlgorithm;
  }

  public boolean isSigned() {
    return signatureAlgorithm != null;
  }

  public byte[] nonce() {
    return C509Cbor.copy(nonce);
  }

  public C509HashedId requestorHash() {
    return requestorHash;
  }

  public C509Extensions extensions() {
    return extensions;
  }

  public List<C509PerIssuerOCSPRequest> requests() {
    return requests;
  }

  /** The embedded certificates of the requestor, or null. */
  public C509CertChainVariant requestorCerts() {
    return requestorCerts;
  }

  @Override
  public InsertionOrderedMap<C509HashedId, List<C509SingleCertRequest>> getRequestedCerts() {
    InsertionOrderedMap<C509HashedId, List<C509SingleCertRequest>> r = new InsertionOrderedMap<>();
    for (C509PerIssuerOCSPRequest perIssuer : requests) {
      r.put(perIssuer.issuerHash(), perIssuer.queries());
    }
    return r;
  }

  public static C509BasicOCSPRequest readRest(CborDecoder in, int length) throws CodecException {
    if (length != 6 && length != 9) {
      throw new CodecException("Basic OCSP request: array length " + length + " not among {6, 9}");
    }

    Integer sigAlg = in.readIntObj();
    if (sigAlg == null) {
      if (length != 6) {
        throw new CodecException("Basic OCSP request: array length " + length + " != 6");
      }
    } else {
      if (length != 9) {
        throw new CodecException("Basic OCSP request: array length " + length + " != 9");
      }
    }

    int hashAlg = in.readInt();
    byte[] nonce = C509Cbor.readBytesOrNull(in);
    C509Extensions extensions = C509Extensions.read(in);
    List<C509PerIssuerOCSPRequest> requests = C509PerIssuerOCSPRequest.readList(in);

    if (sigAlg == null) {
      return new C509BasicOCSPRequest(hashAlg, nonce, extensions, requests);
    } else {
      C509HashedId requestorHash = new C509HashedId(in.readByteString());
      C509CertChainVariant certChain = C509Cbor.orNull(in, C509CertChainVariant::read);
      SignatureValue signatureValue = SignatureValue.read(sigAlg, in);
      return new C509BasicOCSPRequest(hashAlg, nonce, extensions, requests,
          sigAlg, requestorHash, certChain, signatureValue);
    }
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    writeTbs(out);
    if (signatureAlgorithm != null) {
      signatureValue.encode(out);
    }
  }

  /**
   * @param factory the verifier factory.
   */
  public boolean verify(ContentVerifierFactory factory) throws SignatureException {
    if (signatureAlgorithm == null) {
      throw new SignatureException("the OCSP request is not signed");
    }

    try {
      return factory.getForC509(signatureAlgorithm).atomicC509Verify(
              getEncodedTbs(), signatureValue);
    } catch (GeneralSecurityException | GenerationException e) {
      throw new SignatureException("could not verify the signature of "
          + getClass().getSimpleName(), e);
    }
  }


  @Override
  protected void render(C509TextTree out) {
    out.kv("kind", C509OCSPRequest.Kind.BASIC);
    if (signatureAlgorithm == null) {
      out.kv("signature algorithm", "null");
    } else {
      out.kv("signature algorithm", ConstRegistry.SIGNATURE_ALGORITHM.describe(signatureAlgorithm));
    }

    out.kv("hash algorithm", ConstRegistry.HASH_ALGORITHM.describe(hashAlgorithm))
        .hex("nonce", nonce)
        .item("extensions", extensions)
        .items("requests", requests);

    if (signatureAlgorithm != null) {
      out.kv("requestor hash", requestorHash)
        .item("requestor certificates", requestorCerts)
        .external("signature", signatureValue);
    }
  }

  private byte[] getEncodedTbs() {
    try {
      ByteArrayCborEncoder out = new ByteArrayCborEncoder();
      writeTbs(out);
      return out.toByteArray();
    } catch (CodecException e) {
      throw new RuntimeException("shall not happen");
    }
  }

  private void writeTbs(CborEncoder out) throws CodecException {
    boolean signed = signatureAlgorithm != null;
    out.writeArrayStart(signed ? 9 : 6);
    out.writeLong(C509OCSPRequest.Kind.BASIC.code());
    out.writeIntObj(signatureAlgorithm);
    out.writeInt(hashAlgorithm);
    C509Cbor.writeBytesOrNull(out, nonce);
    extensions.encode(out);
    C509Cbor.writeGroups(out, C509PerIssuerOCSPRequest.WIDTH, requests);
    if (signed) {
      out.writeByteString(requestorHash.raw());
      out.writeObject(requestorCerts);
    }
  }

}
