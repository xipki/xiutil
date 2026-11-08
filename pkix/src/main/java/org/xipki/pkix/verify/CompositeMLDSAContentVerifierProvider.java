// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.codec.c509.ConstSignatureAlgorithm;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.crypto.DigestOutputStream;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigUtil;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;

/**
 * Composite MLDSAContent Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final Integer c509AlgId;

    private final DigestOutputStream os;

    private MyContentVerifier(AlgorithmIdentifier algId) throws GenerationException {
      this.algId = algId;
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.ofAlgorithmIdentifier(algId);
      } catch (NoSuchAlgorithmException e) {
        throw new GenerationException("unknown algorithm " +
            algId.getAlgorithm().getId() + ": " + e.getMessage(), e);
      }

      if (!signAlgo.isCompositeMLDSA()) {
        throw new GenerationException("algorithm " +
            algId.getAlgorithm().getId() + " is not composite MLDSA");
      }
      this.c509AlgId = signAlgo.c509AlgorithmIdentifier();
      this.os = new DigestOutputStream(signAlgo.compositeSigAlgoSuite().ph().createDigest());
    }

    private MyContentVerifier(int c509AlgId) throws GenerationException {
      this.c509AlgId = c509AlgId;
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.ofC509AlgorithmIdentifier(c509AlgId);
      } catch (NoSuchAlgorithmException e) {
        throw new GenerationException("unknown algorithm " +
            ConstSignatureAlgorithm.getDesc(c509AlgId) + ": " + e.getMessage(), e);
      }

      if (!signAlgo.isCompositeMLDSA()) {
        throw new GenerationException("algorithm " +
            ConstSignatureAlgorithm.getDesc(c509AlgId) + " is not composite MLDSA");
      }
      this.algId = signAlgo.algorithmIdentifier();
      this.os = new DigestOutputStream(signAlgo.compositeSigAlgoSuite().ph().createDigest());
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public boolean verify(byte[] signature) {
      try {
        byte[] digestValue = os.digest();
        return CompositeSigUtil.verifyHash(verifyKey, context, digestValue, signature);
      } catch (SignatureException ex) {
        return false;
      } catch (GeneralSecurityException ex) {
        throw new RuntimeException(ex.getMessage());
      }
    }

    @Override
    public Integer getC509AlgorithmIdentifier() {
      return c509AlgId;
    }

  } // class EdDSAContentVerifier

  private final CompositeMLDSAPublicKey verifyKey;

  // currently no context is supported
  private final byte[] context = new byte[0];

  public CompositeMLDSAContentVerifierProvider(CompositeMLDSAPublicKey verifyKey) {
    this.verifyKey = Args.notNull(verifyKey, "verifyKey");
  }

  @Override
  public boolean hasAssociatedCertificate() {
    return false;
  }

  @Override
  public boolean isAssociatedCertificateValidOn(Instant time) {
    return false;
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws GenerationException {
    return new MyContentVerifier(verifierAlgorithmIdentifier);
  }

  @Override
  public ContentVerifier getForC509(int verifierAlgorithmIdentifier) throws GenerationException {
    return new MyContentVerifier(verifierAlgorithmIdentifier);
  }

}
