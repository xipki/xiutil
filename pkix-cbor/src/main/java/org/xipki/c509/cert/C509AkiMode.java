// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.cert;

/**
 * Controls the authority key identifier extension that the certificate builder derives from
 * the issuer certificate.
 *
 * @author Lijun Liao (xipki)
 */
public enum C509AkiMode {

  /** No authority key identifier. */
  NONE,

  /** The subject key identifier of the issuer. */
  KEY_ID,

  /** Issuer name and serial number of the issuer certificate. */
  ISSUER_AND_SERIAL,

  /** Key identifier, issuer name and serial number. */
  ALL

}
