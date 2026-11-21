// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.ext.C509AcceptableResponseTypes;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509PreferredSignatureAlgorithms;
import org.xipki.c509.ext.C509PreferredSignatureAlgorithm;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.crypto.EmbedCertsMode;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds simple, unsigned and signed C509 OCSP requests. Request extensions keep the order in
 * which they were added.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509OCSPRequestBuilder {

  private final C509Hasher hasher;

  private final byte[] nonce;

  private final Map<Long, C509Extension> extensions = new LinkedHashMap<>();

  private final List<C509PerIssuerOCSPRequestBuilder> issuers = new ArrayList<>();

  /**
   * @param nonce the nonce, null or empty for none.
   */
  public C509OCSPRequestBuilder(int hashAlgorithm, int hashedIdLength, byte[] nonce)
      throws NoSuchAlgorithmException {
    this.hasher = new C509Hasher(hashAlgorithm, hashedIdLength);
    this.nonce = (nonce == null || nonce.length == 0) ? null : nonce.clone();
  }

  public C509OCSPRequestBuilder acceptableResponseTypes(int... kinds) {
    return extension(ConstExtensionId.acceptableOcspResponseTypes, false,
        new C509AcceptableResponseTypes(kinds));
  }

  public C509OCSPRequestBuilder preferredSignatureAlgorithms(
      C509PreferredSignatureAlgorithm... entries) {
    return extension(ConstExtensionId.ocsp_pref_sig_algs, false,
        new C509PreferredSignatureAlgorithms(Arrays.asList(entries)));
  }

  public C509OCSPRequestBuilder extension(long id, boolean critical, C509ExtnValue value) {
    if (extensions.putIfAbsent(id, new C509Extension(id, critical, value)) != null) {
      throw new IllegalArgumentException(
          "duplicate extension " + ConstExtensionId.describe(id));
    }
    return this;
  }

  public C509PerIssuerOCSPRequestBuilder forIssuer(
      C509Certificate issuer, C509Extensions issuerExtensions) {
    return forIssuer(hasher.hashedIdForCert(issuer), issuerExtensions);
  }

  public C509PerIssuerOCSPRequestBuilder forIssuer(
      C509HashedId issuerHash,
      C509Extensions issuerExtensions) {
    C509PerIssuerOCSPRequestBuilder b = new C509PerIssuerOCSPRequestBuilder(
        Args.notNull(issuerHash, "issuerHash"), issuerExtensions);
    issuers.add(b);
    return b;
  }

  public C509SimpleOCSPRequest buildSimple(
      C509Certificate issuer, BigInteger serialNumber, C509Extensions requestExtensions) {
    return buildSimple(hasher.hashedIdForCert(issuer), serialNumber, requestExtensions);
  }

  public C509SimpleOCSPRequest buildSimple(
      C509HashedId issuerHash, BigInteger serialNumber, C509Extensions requestExtensions) {
    if (!issuers.isEmpty()) {
      throw new IllegalStateException("a simple request cannot contain forIssuer() requests");
    }
    return new C509SimpleOCSPRequest(hasher.algorithm(), nonce, issuerHash, serialNumber,
        requestExtensions);
  }

  public C509BasicOCSPRequest buildUnsigned() {
    return new C509BasicOCSPRequest(hasher.algorithm(), nonce, extensions(), issuerRequests());
  }

  public C509BasicOCSPRequest buildSigned(C509ExtendedSigner signer, EmbedCertsMode embed)
      throws SignatureException {
    return new C509BasicOCSPRequest(hasher, nonce, extensions(), issuerRequests(), signer, embed);
  }

  private C509Extensions extensions() {
    return new C509Extensions(extensions.values());
  }

  private List<C509PerIssuerOCSPRequest> issuerRequests() {
    List<C509PerIssuerOCSPRequest> list = new ArrayList<>(issuers.size());
    issuers.forEach(b -> list.add(b.build()));
    return list;
  }

}
