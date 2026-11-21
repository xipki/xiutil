// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.auth;

import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.X509Cert;

import java.util.Locale;

/**
 * Requestor interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface Requestor {

  enum Protocol {
    CMP,
    EST,
    REST,
    SCEP;

    static Protocol of(String str) {
      str = str.toUpperCase(Locale.ROOT);
      return valueOf(str);
    }
  }

  enum Permission {
    ENROLL_CERT,
    REENROLL_CERT,
    GEN_KEYPAIR,
    ENROLL_CROSS,
    UNSUSPEND_CERT,
    REVOKE_CERT;

    static Permission of(String str) {
      // accept both ENROLL_CERT and enroll-cert
      str = str.toUpperCase(Locale.ROOT).replace('-', '_');
      return valueOf(str);
    }

  }

  /**
   * Returns the name of this requestor. Will not be used internally for any
   * authentication. Only used for internal logging.
   * @return the name of this requestor.
   */
  String name();

  /**
   * Returns whether the requested certificate profile for given CA is allowed.
   * @param certprofile the certprofile name.
   * @param caName the CA name.
   * @return true if allowed, false otherwise.
   */
  boolean isCertprofilePermitted(String caName, String certprofile);

  /**
   * Returns whether all certificate profiles for given CA are allowed. Used if the request
   * specifies no certificate profile, e.g. the CA re-uses the profile of the old certificate.
   * @param caName the CA name.
   * @return true if allowed, false otherwise.
   */
  default boolean isAllCertprofilesPermitted(String caName) {
    return isCertprofilePermitted(caName, "ALL");
  }

  /**
   * Returns whether the requested permissions is allowed.
   * @param permission the permission.
   *
   * @return true if all requested permissions are allowed, false otherwise.
   */
  boolean isPermitted(Permission permission);

  /**
   * Password-based requestor interface. Used for EST, REST and SCEP gateway.
   */
  interface PasswordRequestor extends Requestor {

    boolean authenticate(char[] password);

    boolean authenticate(byte[] password);

  }

  /**
   * Simple password-based requestor interface, used for the CMP gateway.
   */
  interface SimplePasswordRequestor extends Requestor {

    byte[] keyId();

    char[] password();

  }

  /**
   * X.509 Certificate-based requestor interface.
   */
  interface X509CertRequestor extends Requestor {

    byte[] keyId();

    X509Cert cert();

  }

  /**
   * C509 Certificate-based requestor interface.
   */

  interface C509CertRequestor extends Requestor {

    byte[] keyId();

    C509Cert cert();

  }

}
