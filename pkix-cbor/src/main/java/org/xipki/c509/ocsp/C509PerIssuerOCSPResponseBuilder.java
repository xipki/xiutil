// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Collects the certificate answers for one issuer. Created by
 * {@link C509OCSPResponseBuilder#forIssuer}.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerOCSPResponseBuilder {

  private final long producedAt;

  private final C509HashedId issuerHash;

  private final C509Extensions extensions;

  private final List<C509SingleCertResponse> answers = new ArrayList<>();

  C509PerIssuerOCSPResponseBuilder(
      Instant producedAt, C509HashedId issuerHash, C509Extensions extensions) {
    this.producedAt = producedAt.getEpochSecond();
    this.issuerHash = issuerHash;
    this.extensions = extensions;
  }

  /**
   * @param nextUpdate the time of the next update, or null.
   */
  public C509PerIssuerOCSPResponseBuilder answer(
      BigInteger serialNumber, C509CertStatus status, Instant thisUpdate,
      Instant nextUpdate, C509Extension... extensions) {
    answers.add(new C509SingleCertResponse(
        serialNumber, status, thisUpdate.getEpochSecond() - producedAt,
        nextUpdate == null ? null : nextUpdate.getEpochSecond() - producedAt,
        extensions == null || extensions.length == 0
            ? null : new C509Extensions(Arrays.asList(extensions))));
    return this;
  }

  C509PerIssuerOCSPResponse build() {
    return new C509PerIssuerOCSPResponse(issuerHash, extensions, answers);
  }

}
