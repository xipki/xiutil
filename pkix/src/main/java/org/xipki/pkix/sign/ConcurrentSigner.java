// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.exception.NoIdleSignerException;

import java.security.Key;
import java.security.PublicKey;

/**
 * Concurrent Signer interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface ConcurrentSigner extends AtomicContentSigner {

  String name();

  /**
   * Returns the algorithm.
   * @return algorithm
   */
  SignAlgo algorithm();

  boolean isMac();

  byte[] sha1OfMacKey();

  /**
   * Get the signing key.
   * @return the signing key if possible. {@code null} may be returned.
   */
  Key signingKey();

  /**
   * Sets the public key.
   * @param publicKey
   *          Public key of this signer. Must not be {@code null}.
   */
  void setPublicKey(PublicKey publicKey);

  PublicKey publicKey();

  X509Cert x509Cert();

  /**
   * Set the X509 CertificateChain.
   *
   * @param certchain
   *          Certificate chain of this signer. Could be {@code null}.
   */
  void setX509CertChain(X509Cert[] certchain);

  X509Cert[] x509CertChain();

  C509Cert c509Cert();

  /**
   * Set the C509 CertificateChain.
   *
   * @param certchain
   *          Certificate chain of this signer. Could be {@code null}.
   */
  void setC509CertChain(C509Cert[] certchain);

  C509Cert[] c509CertChain();

  /**
   * Initializes me.
   * @param conf
   *          Configuration. Could be {@code null}.
   * @throws XiSecurityException
   *         if error during the initialization occurs.
   */
  void initialize(String conf) throws XiSecurityException;

  /**
   * Borrows a signer with implementation-dependent default timeout.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  Signer borrowSigner() throws NoIdleSignerException;

  /**
   * Borrows a signer with the given {@code soTimeout}.
   * @param soTimeout timeout in milliseconds, 0 for infinitely.
   * @return the signer
   * @throws NoIdleSignerException
   *         If no idle signer is available
   */
  Signer borrowSigner(int soTimeout) throws NoIdleSignerException;

  void requiteSigner(Signer signer);

  boolean isHealthy();

  void close();

  C509ExtendedSigner asC509Signer();

}
