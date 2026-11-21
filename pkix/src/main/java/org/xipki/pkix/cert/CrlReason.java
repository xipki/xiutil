// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x509.CRLReason;
import org.xipki.c509.crl.C509RevocationReason;
import org.xipki.codec.util.Args;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Crl Reason enumeration.
 * is revoked, as defined in <a href="http://www.ietf.org/rfc/rfc3280.txt">
 * RFC 3280: Internet X.509 Public Key Infrastructure Certificate and CRL
 * Profile</a>.
 *
 * @author Lijun Liao (xipki)
 */
public enum CrlReason {

  UNSPECIFIED(CRLReason.unspecified,
      C509RevocationReason.UNSPECIFIED, "unspecified"),
  KEY_COMPROMISE(CRLReason.keyCompromise,
      C509RevocationReason.KEY_COMPROMISE, "keyCompromise"),
  CA_COMPROMISE(CRLReason.cACompromise,
      C509RevocationReason.CA_COMPROMISE, "cACompromise"),
  AFFILIATION_CHANGED(CRLReason.affiliationChanged,
      C509RevocationReason.AFFILIATION_CHANGED, "affiliationChanged"),
  SUPERSEDED(CRLReason.superseded,
      C509RevocationReason.SUPERSEDED, "superseded"),
  CESSATION_OF_OPERATION(CRLReason.cessationOfOperation,
      C509RevocationReason.CESSATION_OF_OPERATION, "cessationOfOperation"),
  CERTIFICATE_HOLD(CRLReason.certificateHold,
      C509RevocationReason.CERTIFICATE_HOLD, "certificateHold"),
  REMOVE_FROM_CRL(CRLReason.removeFromCRL,
      C509RevocationReason.REMOVE_FROM_CRL, "removeFromCRL"),
  PRIVILEGE_WITHDRAWN(CRLReason.privilegeWithdrawn,
      C509RevocationReason.PRIVILEGE_WITHDRAWN, "privilegeWithdrawn"),
  AA_COMPROMISE(CRLReason.aACompromise,
      C509RevocationReason.AA_COMPROMISE, "aACompromise");

  public static final List<CrlReason> PERMITTED_CLIENT_CRLREASONS = List.of(
      CrlReason.UNSPECIFIED,            CrlReason.KEY_COMPROMISE,
      CrlReason.AFFILIATION_CHANGED,    CrlReason.SUPERSEDED,
      CrlReason.CESSATION_OF_OPERATION, CrlReason.CERTIFICATE_HOLD,
      CrlReason.PRIVILEGE_WITHDRAWN);

  private static final Map<Integer, CrlReason> REASONS = new HashMap<>();

  private final CRLReason asn1;

  private final C509RevocationReason c509;

  private final String text;

  static {
    for (CrlReason value : CrlReason.values()) {
      REASONS.put(value.asn1.getValue(), value);
    }
  }

  CrlReason(CRLReason asn1, C509RevocationReason c509, String text) {
    this.asn1 = asn1;
    this.c509 = c509;
    this.text = text;
  }

  public CRLReason asn1() {
    return asn1;
  }

  public C509RevocationReason c509() {
    return c509;
  }

  public String text() {
    return text;
  }

  public int code() {
    return asn1.getValue();
  }

  public String description() {
    return asn1.getEnumeratedName();
  }

  /**
   * Whether the code may be used for a revoked certificate (all but removeFromCRL).
   */
  public static boolean isC509RevocationCode(int code) {
    CrlReason r = REASONS.get(code);
    return r != null && r != REMOVE_FROM_CRL;
  }

  public static CrlReason forReasonCode(int reasonCode) {
    CrlReason ret = REASONS.get(reasonCode);
    if (ret != null) {
      return ret;
    }

    throw new IllegalArgumentException("invalid CrlReason code " + reasonCode);
  }

  public static CrlReason forReason(CRLReason reason) {
    CrlReason ret = REASONS.get(reason.getValue());
    if (ret != null) {
      return ret;
    }

    throw new IllegalArgumentException("invalid CRLReason " + reason);
  }

  public static CrlReason forNameOrText(String text) {
    Args.notNull(text, "text");
    for (CrlReason value : values()) {
      if (value.name().equalsIgnoreCase(text) ||
          Integer.toString(value.asn1.getValue()).equals(text) ||
          value.asn1.getEnumeratedName().equalsIgnoreCase(text)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid CrlReason " + text);
  }

}
