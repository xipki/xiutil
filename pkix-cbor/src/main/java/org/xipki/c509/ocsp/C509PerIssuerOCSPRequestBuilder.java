// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Collects the certificate queries for one issuer. Created by
 * {@link C509OCSPRequestBuilder#forIssuer}.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PerIssuerOCSPRequestBuilder {

  private final C509HashedId issuerHash;

  private final C509Extensions extensions;

  private final List<C509SingleCertRequest> queries = new ArrayList<>();

  C509PerIssuerOCSPRequestBuilder(C509HashedId issuerHash, C509Extensions extensions) {
    this.issuerHash = issuerHash;
    this.extensions = extensions;
  }

  public C509PerIssuerOCSPRequestBuilder query(
      BigInteger serialNumber, C509Extension... extensions) {
    queries.add(new C509SingleCertRequest(serialNumber, extensions == null || extensions.length == 0
        ? null : new C509Extensions(Arrays.asList(extensions))));
    return this;
  }

  C509PerIssuerOCSPRequest build() {
    return new C509PerIssuerOCSPRequest(issuerHash, extensions, queries);
  }

}
