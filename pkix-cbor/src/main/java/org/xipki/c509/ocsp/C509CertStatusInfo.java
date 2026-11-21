// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;

/**
 * The decoded status of one certificate in a C509 OCSP response: serial number, status,
 * thisUpdate and nextUpdate, and the single-response extensions. Unlike the encoded response,
 * where thisUpdate and nextUpdate are offsets in seconds from producedAt, the times here are
 * absolute.
 *
 * @author Lijun Liao (xipki)
 */
public class C509CertStatusInfo {

  private final BigInteger serialNumber;

  private final C509CertStatus status;

  private final Instant thisUpdate;

  private final Instant nextUpdate;

  private final C509Extensions extensions;

  public C509CertStatusInfo(
      BigInteger serialNumber, C509CertStatus status,
      Instant thisUpdate, Instant nextUpdate, C509Extensions extensions) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.status = Args.notNull(status, "status");
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = nextUpdate;
    this.extensions = extensions;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public C509CertStatus status() {
    return status;
  }

  public Instant thisUpdate() {
    return thisUpdate;
  }

  public Instant nextUpdate() {
    return nextUpdate;
  }

  public C509Extensions extensions() {
    return extensions;
  }
}
