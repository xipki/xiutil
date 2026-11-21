// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.SignatureOutputStream;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.util.KeyUtil;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;

/**
 * Signature Signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureSigner implements Signer {

  private final byte[] encodedX509SigAlgId;

  private final ContentSigner signer;

  public SignatureSigner(SignAlgo sigAlgo, Signature signer, PrivateKey key, byte[] context) {
    this(sigAlgo.algorithmIdentifier(), sigAlgo.c509AlgorithmIdentifier(), signer, key, context);
  }

  private static Integer getC509AlgId(AlgorithmIdentifier algId) {
    try {
      SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(algId);
      return signAlgo.c509AlgorithmIdentifier();
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }

  private static boolean isEcdsaOrSm2(AlgorithmIdentifier algId) {
    try {
      SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(algId);
      return signAlgo.isECDSASigAlgo() || signAlgo.isSM2SigAlgo();
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  public SignatureSigner(
      AlgorithmIdentifier sigAlgId, Signature signer, PrivateKey key, byte[] context) {
    this(sigAlgId, getC509AlgId(sigAlgId), signer, key, context);
  }

  private SignatureSigner(
      AlgorithmIdentifier sigAlgId, Integer c509SigAlgId,
      Signature signer, PrivateKey key, byte[] context) {
    Args.notNull(sigAlgId, "sigAlgId");
    Args.notNull(signer, "signer");
    Args.notNull(key, "key");

    this.encodedX509SigAlgId = sigAlgId.getEncoded();

    final boolean dsaSig = isEcdsaOrSm2(sigAlgId);

    // length of r and s in the plain signature: the length of the EC order in bytes.
    final int ecOrderLen = (dsaSig && key instanceof ECPrivateKey)
        ? (((ECPrivateKey) key).getParams().getOrder().bitLength() + 7) / 8
        : 0;

    this.signer = new ContentSigner() {
      private final SignatureOutputStream stream = new SignatureOutputStream(signer);

      @Override
      public AlgorithmIdentifier x509Algorithm() {
        return sigAlgId;
      }

      @Override
      public int c509Algorithm() {
        return ContentSigner.checkC509AlgId(c509SigAlgId, sigAlgId.getAlgorithm());
      }

      @Override
      public OutputStream getOutputStream() {
        try {
          KeyUtil.initSign(signer, key);
          if (context != null) {
            KeyInfoUtil.setContext(signer, context);
          }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
          throw new IllegalStateException("could not initSign", ex);
        }
        return stream;
      }

      @Override
      public byte[] getX509Signature() throws SignatureException {
        return stream.getSignature();
      }

      @Override
      public SignatureValue getC509Signature() throws SignatureException {
        c509Algorithm();
        return x509ToC509Sig(stream.getSignature());
      }

      @Override
      public SignatureValue atomicC509Sign(byte[] dataToSign) throws SignatureException {
        c509Algorithm();
        return x509ToC509Sig(atomicX509Sign(dataToSign));
      }

      /*
       * Converts the ECDSA / SM2 signature from the X9.62 format (DER-encoded
       * SEQUENCE { r INTEGER, s INTEGER }) to the plain format (r || s), where r and s
       * are of the length of the EC order. Signatures of other algorithms are unchanged.
       */
      private SignatureValue x509ToC509Sig(byte[] x509Sig) throws SignatureException {
        if (!dsaSig) {
          return new BytesSignatureValue(x509Sig);
        }

        if (ecOrderLen == 0) {
          throw new SignatureException("could not determine the EC order of the key "
              + key.getClass().getName());
        }

        byte[] plainSig = Asn1Util.dsaSigX962ToPlain(x509Sig, ecOrderLen);
        if (Arrays.equals(plainSig, x509Sig)) {
          // dsaSigX962ToPlain returns the input if it is not a valid X9.62 signature.
          throw new SignatureException("invalid X9.62 DSA signature");
        }
        return new BytesSignatureValue(plainSig);
      }
    };
  }

  /**
   * Creates a {@link ContentSigner} for the software private key.
   * @param signAlgo the signature algorithm.
   * @param key the private key.
   * @return the content signer.
   * @throws XiSecurityException if the signer cannot be created.
   */
  public static ContentSigner newContentSigner(SignAlgo signAlgo, PrivateKey key)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    Signature signature;
    try {
      signature = CryptoApiFactory.get().newSignature(signAlgo.jceName());
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException("could not create Signature for " + signAlgo, e);
    }
    return new SignatureSigner(signAlgo, signature, key, null).contentSigner();
  }

  @Override
  public ContentSigner contentSigner() {
    return signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509SigAlgId, encodedX509SigAlgId.length);
  }

}
