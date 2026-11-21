// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

/**
 * CRL revocation reason codes (RFC 5280).
 * TODO: merge this with CRLReason
 *
 * @author Lijun Liao (xipki)
 */
public enum C509RevocationReason {

  UNSPECIFIED(0, "unspecified"),
  KEY_COMPROMISE(1, "keyCompromise"),
  CA_COMPROMISE(2, "cACompromise"),
  AFFILIATION_CHANGED(3, "affiliationChanged"),
  SUPERSEDED(4, "superseded"),
  CESSATION_OF_OPERATION(5, "cessationOfOperation"),
  CERTIFICATE_HOLD(6, "certificateHold"),
  REMOVE_FROM_CRL(8, "removeFromCRL"),
  PRIVILEGE_WITHDRAWN(9, "privilegeWithdrawn"),
  AA_COMPROMISE(10, "aACompromise");

  private final int code;

  private final String x509Name;

  C509RevocationReason(int code, String x509Name) {
    this.code = code;
    this.x509Name = x509Name;
  }

  public int code() {
    return code;
  }

  public String x509Name() {
    return x509Name;
  }

  /** Returns the reason, or null for an unknown code. */
  public static C509RevocationReason of(int code) {
    for (C509RevocationReason r : values()) {
      if (r.code == code) {
        return r;
      }
    }
    return null;
  }

  public static String nameOf(int code) {
    C509RevocationReason r = of(code);
    return r == null ? Integer.toString(code) : r.x509Name;
  }

  /**
   * Whether the code may be used for a revoked certificate (all but removeFromCRL).
   */
  public static boolean isRevocationCode(int code) {
    C509RevocationReason r = of(code);
    return r != null && r != REMOVE_FROM_CRL;
  }

}
