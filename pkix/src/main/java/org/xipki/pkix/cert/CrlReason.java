// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x509.CRLReason;
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

  /**
   * This reason indicates that it is unspecified as to why the
   * certificate has been revoked.
   */
  UNSPECIFIED(CRLReason.unspecified),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to end-entity certificates only.
   */
  KEY_COMPROMISE(CRLReason.keyCompromise),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to certificate authority (CA) certificates only.
   */
  CA_COMPROMISE(CRLReason.cACompromise),

  /**
   * This reason indicates that the subject's name or other information
   * has changed.
   */
  AFFILIATION_CHANGED(CRLReason.affiliationChanged),

  /**
   * This reason indicates that the certificate has been superseded.
   */
  SUPERSEDED(CRLReason.superseded),

  /**
   * This reason indicates that the certificate is no longer needed.
   */
  CESSATION_OF_OPERATION(CRLReason.cessationOfOperation),

  /**
   * This reason indicates that the certificate has been put on hold.
   */
  CERTIFICATE_HOLD(CRLReason.certificateHold),

  /**
   * This reason indicates that the certificate was previously on hold
   * and should be removed from the CRL. It is for use with delta CRLs.
   */
  REMOVE_FROM_CRL(CRLReason.removeFromCRL),

  /**
   * This reason indicates that the privileges granted to the subject of
   * the certificate have been withdrawn.
   */
  PRIVILEGE_WITHDRAWN(CRLReason.privilegeWithdrawn),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to authority attribute (AA) certificates only.
   */
  AA_COMPROMISE(CRLReason.aACompromise);

  public static final List<CrlReason> PERMITTED_CLIENT_CRLREASONS = List.of(
      CrlReason.UNSPECIFIED,            CrlReason.KEY_COMPROMISE,
      CrlReason.AFFILIATION_CHANGED,    CrlReason.SUPERSEDED,
      CrlReason.CESSATION_OF_OPERATION, CrlReason.CERTIFICATE_HOLD,
      CrlReason.PRIVILEGE_WITHDRAWN);

  private static final Map<Integer, CrlReason> REASONS = new HashMap<>();

  private final CRLReason asn1;

  CrlReason(CRLReason asn1) {
    this.asn1 = asn1;
  }

  public CRLReason asn1() {
    return asn1;
  }

  public int code() {
    return asn1.getValue();
  }

  public String description() {
    return asn1.getEnumeratedName();
  }

  static {
    for (CrlReason value : CrlReason.values()) {
      REASONS.put(value.asn1.getValue(), value);
    }
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
