// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Instant;

/**
 * Signature Content Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureContentVerifierProvider implements ContentVerifierProvider {

  private static final Logger LOG = LoggerFactory.getLogger(SignatureContentVerifierProvider.class);

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private static class MyContentVerifier implements ContentVerifier {

    private final String algorithm;

    private final AlgorithmIdentifier algId;

    private final ByteArrayOutputStream outstream;

    private final PublicKey verifyKey;

    private MyContentVerifier(AlgorithmIdentifier algId, PublicKey verifyKey) {
      this.algId = algId;
      try {
        this.algorithm = SignAlgo.ofAlgorithmIdentifier(algId).jceName();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("unknown algorithm " +
            algId.getAlgorithm().getId() + ": " + e.getMessage(), e);
      }
      this.outstream = new ByteArrayOutputStream();
      this.verifyKey = verifyKey;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      outstream.reset();
      return outstream;
    }

    @Override
    public boolean verify(byte[] signature) throws SignatureException {
      return atomicVerify(outstream.toByteArray(), signature);
    }

    @Override
    public boolean atomicVerify(byte[] toBeSignData, byte[] signature) throws SignatureException {
      try {
        Signature sig = cryptoApi.newSignature(algorithm);
        sig.initVerify(verifyKey);
        sig.update(toBeSignData);
        return sig.verify(signature);
      } catch (SignatureException ex) {
        LOG.warn("could not verify signature", ex);
        return false;
      } catch (GeneralSecurityException ex) {
        LOG.warn("could not verify signature", ex);
        throw new RuntimeException(ex.getMessage());
      }
    }

  } // class EdDSAContentVerifier

  private final PublicKey verifyKey;

  private final Certificate associatedCert;

  public SignatureContentVerifierProvider(PublicKey verifyKey) {
    this(verifyKey, null);
  }

  /**
   * Constructor.
   * @param verifyKey the public key to verify the signature.
   * @param associatedCert the certificate of the public key, may be {@code null}.
   */
  public SignatureContentVerifierProvider(PublicKey verifyKey, Certificate associatedCert) {
    this.verifyKey = Args.notNull(verifyKey, "verifyKey");
    this.associatedCert = associatedCert;
  }

  @Override
  public boolean hasAssociatedCertificate() {
    return associatedCert != null;
  }

  @Override
  public boolean isAssociatedCertificateValidOn(Instant time) {
    return associatedCert != null && associatedCert.isValidOn(time);
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws GenerationException {
    return new MyContentVerifier(verifierAlgorithmIdentifier, verifyKey);
  }

}
