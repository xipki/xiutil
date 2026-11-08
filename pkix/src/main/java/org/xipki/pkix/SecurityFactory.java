// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix;

import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.CsrControl;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.verify.AlgorithmValidator;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Set;

/**
 * Security Factory interface.
 * {@link ConcurrentSigner}, {@link ContentVerifierProvider},
 * to verify POP, to the random, etc.
 *
 * @author Lijun Liao (xipki)
 */
public interface SecurityFactory {

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  Set<String> supportedSignerTypes();

  /**
   * Creates signer.
   *
   * @param type
   *        Type of the signer. Must not be {@code null}.
   * @param conf
   *        Configuration of the signer. Could be {@code null}.
   * @param cert
   *        Certificate of the signer. If not {@code null}, it will be used;
   *        otherwise the certificates contained in the token will be used.
   * @return the new signer
   * @throws GenerationException if could not create the signer
   */
  default ConcurrentSigner createSigner(String type, SignerConf conf, X509Cert cert)
      throws GenerationException {
    X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
    return createSigner(type, conf, certs);
  }

  /**
   * Creates signer.
   *
   * @param type
   *        Type of the signer. Must not be {@code null}.
   * @param conf
   *        Configuration of the signer. Could be {@code null}.
   * @param certs
   *        Certificates of the signer. If not {@code null}, it will be used;
   *        otherwise the certificates contained in the token will be used.
   * @return the new signer
   * @throws GenerationException
   *         if could not create the signer
   */
  ConcurrentSigner createSigner(String type, SignerConf conf, X509Cert[] certs)
      throws GenerationException;

  /**
   * Gets the ContentVerifierProvider from the public key.
   *
   * @param publicKey
   *        Signature verification key. Must not be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey is invalid or unsupported.
   */
  default ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null, null);
  }

  /**
   * Gets the ContentVerifierProvider from the public key.
   *
   * @param publicKey
   *        Signature verification key. Must not be {@code null}.
   * @param ownerKeyAndCert
   *        The owner's key and certificate for the CSR with Diffie-Hellman PoP.
   *        May be {@code null}.
   * @param ownerMasterKey
   *        The owner's master key and certificate for the CSR with KEM PoP.
   *        May be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey is invalid or unsupported.
   */
  ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey)
      throws InvalidKeyException;

  /**
   * Gets the ContentVerifierProvider from the certificate.
   *
   * @param cert
   *        Certificate that contains the signature verification key. Must not
   *        be {@code null}.
   * @return the ContentVerifierProvider
   * @throws InvalidKeyException
   *         If the publicKey contained in the certificate is invalid or
   *         unsupported.
   */
  default ContentVerifierProvider getContentVerifierProvider(X509Cert cert)
      throws InvalidKeyException {
    try {
      return getContentVerifierProvider( Args.notNull(cert, "cert").publicKey());
    } catch (RuntimeException e) {
      throw new InvalidKeyException(e);
    }
  }

  /**
   * Verifies the signature of CSR.
   * @param csr
   *        CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *        Signature algorithms validator. null to accept all
   *        algorithms
   * @return true if the signature is valid and the signature
   *         algorithm is accepted, false otherwise.
   */
  default boolean verifyPop(CertificationRequest csr, AlgorithmValidator algoValidator) {
    return verifyPop(csr, algoValidator, null, null);
  }

  /**
   * Verifies the signature of CSR.
   *
   * @param csr
   *        CSR to be verified. Must not be {@code null}.
   * @param algoValidator
   *        Signature algorithms validator. null to accept all
   *        algorithms
   * @param ownerKeyAndCert
   *        The owner's key and certificate for the CSR with Diffie-Hellman PoP.
   *        May be {@code null}.
   * @param ownerMasterKey
   *        The ower's secret key for the CSR with KEM-MAC PoP.
   *        May be {@code null}.
   * @return true if the signature is valid and the signature
   *         algorithm is accepted, false otherwise.
   */
  boolean verifyPop(CertificationRequest csr, AlgorithmValidator algoValidator,
                    DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey);

  /**
   * Create PublicKey from the {@code subjectPublicKeyInfo}.
   * @param subjectPublicKeyInfo
   *        From which the public key will be created. Must not be {@code null}.
   * @return the created public key.
   * @throws InvalidKeyException
   *         if could not create public key.
   */
  PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws InvalidKeyException;

  int dfltSignerParallelism();

  CsrControl csrControl();

}
