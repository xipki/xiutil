// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.sign;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.ocsp.C509HashedId;
import org.xipki.codec.c509.SignatureValue;

import java.security.SignatureException;

/**
 * Produces C509 signature values.
 *
 * @author Lijun Liao (xipki)
 */
public interface C509ExtendedSigner {

  byte[] certHash(int c509HashAlg);

  /** The C509 signature algorithm identifier. */
  int c509Algorithm();

  SignatureValue c509Sign(byte[] tbs) throws SignatureException;

  /**
   * The certificate chain of the signer, signer certificate first; null if unknown.
   */
  default CoseC509 certificates() {
    return null;
  }

  default CoseC509 requireCertificates() {
    CoseC509 certs = certificates();
    if (certs == null) {
      throw new IllegalStateException("the signer has no certificates");
    }
    return certs;
  }

  default C509Certificate requireCertificate() {
    return requireCertificates().first();
  }

  default boolean isHealthy() {
    return true;
  }

}
