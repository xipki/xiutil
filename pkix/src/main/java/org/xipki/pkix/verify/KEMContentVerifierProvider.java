// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.c509.ConstSignatureAlgorithm;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.pkix.sign.KemHmacSignature;

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
public class KEMContentVerifierProvider implements ContentVerifierProvider {

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
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithm.algorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      return verifier.contentSigner().getOutputStream();
    }

    @Override
    public boolean verify(byte[] expected) throws SignatureException {
      KemHmacSignature expectedSig;
      try {
        expectedSig = KemHmacSignature.decode(expected);
      } catch (CodecException e) {
        return false;
      }

      byte[] rawSignature = expectedSig.signature();
      byte[] computedMacValue = verifier.contentSigner().getSignature();
      return MessageDigest.isEqual(rawSignature, computedMacValue);
    }

    @Override
    public Integer getC509AlgorithmIdentifier() {
      return algorithm.c509AlgorithmIdentifier();
    }

  } // class MyContentVerifier

  private final SecretKey macKey;

  public KEMContentVerifierProvider(PublicKey verifyKey, SecretKey ownerMasterKey) {
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
          + ConstSignatureAlgorithm.getDesc(verifierAlgorithmIdentifier));
    }

    return new MyContentVerifier();
  }

}
