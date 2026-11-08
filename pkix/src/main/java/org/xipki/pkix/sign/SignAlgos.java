// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.SignAlgoMode;
import org.xipki.pkix.pkcs11.P11CompositeKey;
import org.xipki.pkix.pkcs11.P11Key;
import org.xipki.codec.exception.InvalidConfException;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Detects the signature algorithm of PKCS#11 keys with the signer configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class SignAlgos {

  private SignAlgos() {
  }

  public static SignAlgo getInstance(Key key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    if (signerConf == null) {
      return SignAlgo.ofKey(key);
    }

    try {
      SignAlgo algo = signerConf.algo();
      return (algo != null) ? SignAlgo.getInstance(key, algo, null, null)
          : SignAlgo.getInstance(key, null, signerConf.mode(), signerConf.hash());
    } catch (InvalidConfException e) {
      throw new NoSuchAlgorithmException(e);
    }
  }

  public static SignAlgo getInstance(P11Key p11Key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    SignAlgo algo = null;
    SignAlgoMode mode = null;
    HashAlgo hashAlgo = null;

    if (signerConf != null) {
      try {
        algo = signerConf.algo();
        if (algo == null) {
          mode = signerConf.mode();
          hashAlgo = signerConf.hash();
        }
      } catch (InvalidConfException e) {
        throw new NoSuchAlgorithmException(e);
      }
    }

    long keyType = p11Key.key().id().getKeyType();
    if (keyType == PKCS11T.CKK_RSA) {
      return SignAlgo.checkRSASignAlgo(algo, mode, hashAlgo,
          p11Key.key().rsaModulus().bitLength());
    } else if (keyType == PKCS11T.CKK_EC || keyType == PKCS11T.CKK_VENDOR_SM2
        || keyType == PKCS11T.CKK_EC_EDWARDS) {
      return SignAlgo.checkECSignAlgo(algo, hashAlgo, p11Key.ecParams());
    } else if (keyType == PKCS11T.CKK_ML_DSA) {
      Long variant = p11Key.key().pqcVariant();
      if (variant == null) {
        throw new NoSuchAlgorithmException("P11 MLDSA Variant is not present");
      }

      String paramSpec;
      if (variant == PKCS11T.CKP_ML_DSA_44) {
        paramSpec = "ML-DSA-44";
      } else if (variant == PKCS11T.CKP_ML_DSA_65) {
        paramSpec = "ML-DSA-65";
      } else if (variant == PKCS11T.CKP_ML_DSA_87) {
        paramSpec = "ML-DSA-87";
      } else {
        throw new NoSuchAlgorithmException("unsupported MLDSA Variant " + variant);
      }

      return SignAlgo.checkMLDSASignAlgo(algo, hashAlgo, paramSpec);
    } else if (keyType == PKCS11T.CKK_ML_KEM) {
      if (algo != null && algo != SignAlgo.KEM_HMAC_SHA256) {
        throw new NoSuchAlgorithmException(algo + " != KEM_HMAC_SHA256");
      }
      return SignAlgo.KEM_HMAC_SHA256;
    } else {
      throw new NoSuchAlgorithmException("Unknown key type " + PKCS11T.ckkCodeToName(keyType));
    }
  }

  public static SignAlgo getInstance(P11CompositeKey p11Key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    try {
      SignAlgo algo = (signerConf == null) ? null : signerConf.algo();
      CompositeSigSuite algoSuite = p11Key.sigAlgoSuite();
      if (algoSuite != null) {
        if (algo != null) {
          if (algo.compositeSigAlgoSuite() != algoSuite) {
            throw new NoSuchAlgorithmException("compositeSigAlgoSuite unmatch");
          }
          return algo;
        } else {
          return SignAlgo.getSignAlgo(algoSuite);
        }
      } else if (signerConf != null) {
        KeySpec keySpec = p11Key.kemAlgoSuite().keySpec();
        return SignAlgo.getDefaultSignAlgo(keySpec, signerConf.mode());
      } else {
        throw new NoSuchAlgorithmException("could not detect SignAlgo for P11CompositeKey");
      }
    } catch (InvalidConfException e) {
      throw new NoSuchAlgorithmException(e);
    }
  }

}
