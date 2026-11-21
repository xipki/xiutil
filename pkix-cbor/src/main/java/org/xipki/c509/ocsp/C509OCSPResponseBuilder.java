// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.cert.CoseC509;
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
import java.security.SignatureException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds basic and simple C509 OCSP responses. Response extensions are sorted by ID.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509OCSPResponseBuilder {

  private final int hashAlgorithm;

  private final byte[] nonce;

  private final Instant producedAt;

  private final Map<Long, C509Extension> extensions = new LinkedHashMap<>();

  private final List<C509PerIssuerOCSPResponseBuilder> issuers = new ArrayList<>();

  /**
   * @param producedAt the production time, null for now.
   * @param nonce      the nonce, null or empty for none.
   */
  public C509OCSPResponseBuilder(int hashAlgorithm, Instant producedAt, byte[] nonce) {
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = (nonce == null || nonce.length == 0) ? null : nonce.clone();
    this.producedAt = (producedAt == null ? Instant.now() : producedAt)
        .truncatedTo(ChronoUnit.SECONDS);
  }

  public C509OCSPResponseBuilder acceptableResponseTypes(int... kinds) {
    return extension(ConstExtensionId.acceptableOcspResponseTypes, false,
        new C509AcceptableResponseTypes(kinds));
  }

  public C509OCSPResponseBuilder preferredSignatureAlgorithms(
      C509PreferredSignatureAlgorithm... entries) {
    return extension(ConstExtensionId.ocsp_pref_sig_algs, false,
        new C509PreferredSignatureAlgorithms(Arrays.asList(entries)));
  }

  public C509OCSPResponseBuilder extension(long id, boolean critical, C509ExtnValue value) {
    if (extensions.putIfAbsent(id, new C509Extension(id, critical, value)) != null) {
      throw new IllegalArgumentException(
          "duplicate extension " + ConstExtensionId.describe(id));
    }
    return this;
  }

  public C509PerIssuerOCSPResponseBuilder forIssuer(
      C509HashedId issuerHash,
      C509Extensions issuerExtensions) {
    C509PerIssuerOCSPResponseBuilder b = new C509PerIssuerOCSPResponseBuilder(producedAt,
        Args.notNull(issuerHash, "issuerHash"), issuerExtensions);
    issuers.add(b);
    return b;
  }

  /**
   * Builds a response for exactly one certificate.
   *
   * @param nextUpdate the time of the next update, or null.
   */
  public C509SimpleOCSPResponse buildSimple(
      C509HashedId issuerHash, BigInteger serialNumber, C509CertStatus status,
      Instant thisUpdate, Instant nextUpdate, C509ExtendedSigner signer,
      EmbedCertsMode embed, C509Extensions answerExtensions)
      throws SignatureException {
    if (!issuers.isEmpty()) {
      throw new IllegalStateException("a simple response cannot contain forIssuer() answers");
    }

    C509HashedId signerId = C509HashedId.truncate(
        signer.certHash(hashAlgorithm), issuerHash.length());

    CoseC509 certs = signer.requireCertificates();
    long base = producedAt.getEpochSecond();
    C509SingleCertResponse answer = new C509SingleCertResponse(serialNumber, status,
        thisUpdate.getEpochSecond() - base,
        nextUpdate == null ? null : nextUpdate.getEpochSecond() - base, answerExtensions);
    C509TBSSimpleOCSPResponse body = new C509TBSSimpleOCSPResponse(
        signer.c509Algorithm(), hashAlgorithm, nonce, signerId, issuerHash, producedAt, answer,
        C509CertChainVariant.select(embed, certs));
    return new C509SimpleOCSPResponse(body, signer.c509Sign(body.getEncoded()));
  }

  public C509BasicOCSPResponse buildBasic(C509ExtendedSigner signer, EmbedCertsMode embed)
      throws SignatureException {
    CoseC509 certs = signer.requireCertificates();
    List<C509PerIssuerOCSPResponse> responses = new ArrayList<>(issuers.size());
    issuers.forEach(b -> responses.add(b.build()));
    C509Extensions thisExtns = extensions.isEmpty() ? C509Extensions.EMPTY
        : C509Extensions.sorted(extensions.values());

    C509HashedId signerId = C509HashedId.truncate(
        signer.certHash(hashAlgorithm), responses.get(0).issuerHash().length());
    C509TBSBasicOCSPResponse body = new C509TBSBasicOCSPResponse(
        signer.c509Algorithm(), hashAlgorithm, nonce, signerId, producedAt,
        thisExtns, responses, C509CertChainVariant.select(embed, certs));
    return new C509BasicOCSPResponse(body, signer.c509Sign(body.getEncoded()));
  }

}
