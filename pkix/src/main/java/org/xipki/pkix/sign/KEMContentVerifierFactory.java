// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.x509.id.XipkiOIDs;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.XiSecurityException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.time.Instant;

/**
 * KEMContent Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class KEMContentVerifierFactory implements ContentVerifierFactory {

  private class MyContentVerifier implements ContentVerifier {

    private final SignAlgo algorithm = SignAlgo.KEM_HMAC_SHA256;

    private final HmacSigner verifier;

    private MyContentVerifier() throws GenerationException {
      try {
        this.verifier = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
      } catch (XiSecurityException e) {
        throw new GenerationException(e);
      }
    }

    @Override
    public AlgorithmIdentifier x509Algorithm() {
      return algorithm.algorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      return verifier.contentSigner().getOutputStream();
    }

    @Override
    public boolean x509Verify(byte[] expected) throws SignatureException {
      KemHmacSignature expectedSig;
      try {
        expectedSig = KemHmacSignature.decode(expected);
      } catch (CodecException e) {
        return false;
      }

      byte[] rawSignature = expectedSig.signature();
      byte[] computedMacValue = verifier.contentSigner().getX509Signature();
      return MessageDigest.isEqual(rawSignature, computedMacValue);
    }

    @Override
    public int c509Algorithm() {
      return ContentSigner.checkC509AlgId(algorithm.c509AlgorithmIdentifier(), algorithm);
    }

  } // class MyContentVerifier

  private final SecretKey macKey;

  public KEMContentVerifierFactory(PublicKey verifyKey, SecretKey ownerMasterKey) {
    Args.notNull(verifyKey, "verifyKey");
    Args.notNull(ownerMasterKey, "ownerMasterKey");

    SubjectPublicKeyInfo subjectPublicKeyInfo;
    try {
      subjectPublicKeyInfo = SubjectPublicKeyInfo.fromPublicKey(verifyKey);
    } catch (CodecException e) {
      throw new IllegalArgumentException("could not parse encoded PublicKey", e);
    }
    byte[] rawPkData = subjectPublicKeyInfo.subjectPublicKey();

    byte[] secret = KemUtil.hmacDerive(ownerMasterKey, 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    macKey = new SecretKeySpec(secret, "HMAC");
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
    Asn1Oid oid = verifierAlgorithmIdentifier.getAlgorithm();
    if (!XipkiOIDs.id_alg_KEM_HMAC_SHA256.equals(oid)) {
      throw new GenerationException("unsupported verifierAlgorithmIdentifier " + oid.getId());
    }
    return new MyContentVerifier();
  }

  @Override
  public ContentVerifier getForC509(int verifierAlgorithmIdentifier) throws GenerationException {
    if (ConstSignatureAlgorithm.SIG_KEM_GMAC_256 != verifierAlgorithmIdentifier) {
      throw new GenerationException("unsupported verifierAlgorithmIdentifier "
          + ConstSignatureAlgorithm.describe(verifierAlgorithmIdentifier));
    }

    return new MyContentVerifier();
  }

}
