// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.DigestOutputStream;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.crypto.core.Pkcs1Util;
import org.xipki.util.misc.LogUtil;
import org.xipki.util.misc.RandomUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;
import static org.xipki.crypto.core.SignAlgo.*;

/**
 * PKCS#11 {@link Signer}.
 *
 * @author Lijun Liao (xipki)
 */
abstract class P11Signer implements Signer {

  private static final Logger LOG = LoggerFactory.getLogger(P11Signer.class);

  protected final P11Key identity;

  protected final SignAlgo signAlgo;

  protected final byte[] encodedX509AlgId;

  private P11Signer(P11Key identity, SignAlgo signAlgo) {
    this.identity = Args.notNull(identity, "identity");
    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
  }

  static P11Signer newInstance(
      SecurityFactory securityFactory, P11Key identity, SignerConf conf,
      SignAlgo signAlgo, PublicKey publicKey) throws XiSecurityException {
    return newInstance(securityFactory, identity, conf, signAlgo, publicKey, null);
  }

  static P11Signer newInstance(
      SecurityFactory securityFactory, P11Key identity, SignerConf conf,
      SignAlgo signAlgo, PublicKey publicKey, byte[] context) throws XiSecurityException {
    long keyType = identity.key().id().getKeyType();
    if (keyType == CKK_RSA) {
      return signAlgo.isRSAPSSSigAlgo() ? new RSAPSS(identity, signAlgo)
          : new RSAPkcs1v1_5(identity, signAlgo);
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2) {
      boolean isSm2p256v1 = (keyType == CKK_VENDOR_SM2) || EcCurveEnum.SM2 == identity.ecParams();

      if (isSm2p256v1) {
        if (publicKey == null) {
          publicKey = Optional.ofNullable(identity.publicKey())
              .orElseThrow(() -> new XiSecurityException(
                  "SM2 signer needs public key, but could not get anyone."));
        }

        ECPoint w = ((ECPublicKey) publicKey).getW();
        return new SM2(identity, signAlgo, w.getAffineX(), w.getAffineY());
      } else {
        return new ECDSA(identity, signAlgo);
      }
    } else if (keyType == CKK_EC_EDWARDS) {
      EcCurveEnum curve = identity.ecParams();
      boolean match = (curve == EcCurveEnum.ED25519) ? signAlgo == ED25519 : signAlgo == ED448;

      if (!match) {
        throw new XiSecurityException("key is not suitable for the sign algo " + signAlgo);
      }

      return new EdDSA(identity, signAlgo);
    } else if (keyType == CKK_ML_DSA) {
      Long variant = identity.key().pqcVariant();
      boolean match = false;
      if (variant != null) {
        match = (signAlgo == MLDSA44) ? variant == CKP_ML_DSA_44
              : (signAlgo == MLDSA65) ? variant == CKP_ML_DSA_65
              :  signAlgo == MLDSA87 && variant == CKP_ML_DSA_87;
      }

      if (!match) {
        throw new XiSecurityException("key is not suitable for the sign algo " + signAlgo);
      }

      return new MLDSA(identity, signAlgo, context);
    } else if (keyType == CKK_ML_KEM) {
      SubjectPublicKeyInfo publicKeyInfo;
      try {
        publicKeyInfo = SubjectPublicKeyInfo.fromPublicKey(identity.publicKey());
      } catch (CodecException e) {
        throw new XiSecurityException("could not parse encoded PublicKey", e);
      }
      KemEncapKey encapKey = securityFactory.csrControl().generateKemEncapKey(publicKeyInfo);
      return new P11KemHmacSigner(identity, signAlgo, encapKey);
    } else if (keyType == CKK_AES || keyType == CKK_GENERIC_SECRET) {
      return new Mac(identity, signAlgo);
    } else {
      throw new XiSecurityException("unsupported key type " + ckkCodeToName(keyType));
    }
  }

  @Override
  public final byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  private static class ECDSA extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final OutputStream outputStream;

    private final long mechanism;

    private final MyContentSigner x509Signer;

    static {
      algoMechMap.put(ECDSA_SHA1,   CKM_ECDSA_SHA1);
      algoMechMap.put(ECDSA_SHA224, CKM_ECDSA_SHA224);
      algoMechMap.put(ECDSA_SHA256, CKM_ECDSA_SHA256);
      algoMechMap.put(ECDSA_SHA384, CKM_ECDSA_SHA384);
      algoMechMap.put(ECDSA_SHA512, CKM_ECDSA_SHA512);
      algoMechMap.put(ECDSA_SHA3_224, CKM_ECDSA_SHA3_224);
      algoMechMap.put(ECDSA_SHA3_256, CKM_ECDSA_SHA3_256);
      algoMechMap.put(ECDSA_SHA3_384, CKM_ECDSA_SHA3_384);
      algoMechMap.put(ECDSA_SHA3_512, CKM_ECDSA_SHA3_512);
    } // method static

    ECDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isECDSASigAlgo()) {
        throw new XiSecurityException("not an ECDSA algorithm: " + signAlgo);
      }

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_ECDSA)) {
        mechanism = CKM_ECDSA;
        this.outputStream = new DigestOutputStream(signAlgo.hashAlgo().createDigest());
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      this.x509Signer = new MyContentSigner();
    } // method constructor

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private byte[] getPlainSignature() throws TokenException {
      byte[] dataToSign;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        dataToSign = ((DigestOutputStream) outputStream).digest();
        ((DigestOutputStream) outputStream).reset();
      }

      return identity.sign(mechanism, null, dataToSign);
    }

    private byte[] getPlainSignature(byte[] toBeSignData) throws SignatureException {
      byte[] dataToSign;

      try {
        if (outputStream instanceof ByteArrayOutputStream) {
          // raw data
          dataToSign = toBeSignData;
        } else {
          DigestOutputStream dos = ((DigestOutputStream) outputStream);
          dos.reset();
          dos.write(toBeSignData);
          dataToSign = dos.digest();
        }

        return identity.sign(mechanism, null, dataToSign);
      } catch (TokenException | IOException e) {
        throw new SignatureException(e.getMessage(), e);
      }
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        if (outputStream instanceof ByteArrayOutputStream) {
          ((ByteArrayOutputStream) outputStream).reset();
        } else {
          ((DigestOutputStream) outputStream).reset();
        }
        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        try {
          return dsaSigPlainToX962(getPlainSignature());
        } catch (SignatureException ex) {
          LogUtil.warn(LOG, ex);
          throw ex;
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public byte[] atomicSign(byte[] toBeSignData) throws SignatureException {
        try {
          return dsaSigPlainToX962(getPlainSignature(toBeSignData));
        } catch (SignatureException ex) {
          LogUtil.warn(LOG, ex);
          throw ex;
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public byte[] getC509Signature() throws SignatureException {
        try {
          return getPlainSignature();
        } catch (TokenException ex) {
          LogUtil.warn(LOG, ex);
          throw new SignatureException(ex);
        }
      }

      @Override
      public byte[] atomicC509Sign(byte[] dataToSign) throws SignatureException {
        return getPlainSignature(dataToSign);
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }

    }

  } // method ECDSA

  private static class EdDSA extends P11Signer {

    private static final P11Params.P11EddsaParams ed448Params =
        new P11Params.P11EddsaParams(false, null);

    private final long mechanism;

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    private final MyContentSigner x509Signer;

    EdDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (SignAlgo.ED25519 != signAlgo && ED448 != signAlgo) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      mechanism = CKM_EDDSA;
      if (!identity.supportsSign(mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      this.x509Signer = new MyContentSigner();
    }

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        outputStream.reset();
        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        byte[] content = outputStream.toByteArray();
        outputStream.reset();
        return atomicSign(content);
      }

      @Override
      public byte[] atomicSign(byte[] dataToSign) throws SignatureException {
        try {
          P11Params params = null;
          if (signAlgo == ED448) {
            params = ed448Params;
          }

          return identity.sign(mechanism, params, dataToSign);
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }
    }

  } // class EdDSA

  private static class MLDSA extends P11Signer {

    private final byte[] context;
    private final long mechanism;
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private final MyContentSigner x509Signer;

    MLDSA(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      this(identity, signAlgo, null);
    }

    MLDSA(P11Key identity, SignAlgo signAlgo, byte[] context) throws XiSecurityException {
      super(identity, signAlgo);
      this.context = context == null ? new byte[0] : context.clone();

      this.mechanism = CKM_ML_DSA;
      if (!identity.supportsSign(this.mechanism)) {
        throw new XiSecurityException("unsupported signature algorithm " + signAlgo);
      }

      this.x509Signer = new MyContentSigner();
    }

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        outputStream.reset();
        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        byte[] content = outputStream.toByteArray();
        outputStream.reset();
        return atomicSign(content);
      }

      @Override
      public byte[] atomicSign(byte[] toBeSignData) throws SignatureException {
        try {
          P11Params params = (toBeSignData.length == 0) ? null
              : new P11Params.P11SignAdditionalContext(context);
          return identity.sign(mechanism, params, toBeSignData);
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }
    }

  } // class MLDSA

  private static class P11KemHmacSigner extends P11Signer {

    private final KemHmacSigner signer;

    P11KemHmacSigner(P11Key identity, SignAlgo signAlgo, KemEncapKey encapKey)
        throws XiSecurityException {
      super(identity, signAlgo);
      long mechanism = CKM_ML_KEM;
      if (!identity.supportsDecapsulate(mechanism)) {
        throw new XiSecurityException("unsupported mechanism CKM_ML_KEM");
      }

      byte[] decapKeyValue;
      try {
        decapKeyValue = identity.decapsulateKey(mechanism, null,
            encapKey.encapulation().encapKey(), 32);
      } catch (TokenException e) {
        throw new XiSecurityException(e);
      }

      byte[] secret = KemUtil.doKemDecryptSecret(decapKeyValue, encapKey.encapulation());
      SecretKey macKey = new SecretKeySpec(secret, "AES");
      this.signer = new KemHmacSigner(encapKey.id(), macKey);
    }

    @Override
    public ContentSigner contentSigner() {
      return signer.contentSigner();
    }
  } // class MLKEM

  private static class Mac extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    private final MyContentSigner x509Signer;

    static {
      algoMechMap.put(HMAC_SHA1,   CKM_SHA_1_HMAC);
      algoMechMap.put(HMAC_SHA224, CKM_SHA224_HMAC);
      algoMechMap.put(HMAC_SHA256, CKM_SHA256_HMAC);
      algoMechMap.put(HMAC_SHA384, CKM_SHA384_HMAC);
      algoMechMap.put(HMAC_SHA512, CKM_SHA512_HMAC);
      algoMechMap.put(HMAC_SHA3_224, CKM_SHA3_224_HMAC);
      algoMechMap.put(HMAC_SHA3_256, CKM_SHA3_256_HMAC);
      algoMechMap.put(HMAC_SHA3_384, CKM_SHA3_384_HMAC);
      algoMechMap.put(HMAC_SHA3_512, CKM_SHA3_512_HMAC);
    } // method static

    Mac(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      this.mechanism = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException("Unsupported MAC algorithm " + signAlgo));

      if (!identity.supportsSign(mechanism)) {
        throw new XiSecurityException("unsupported MAC algorithm " + signAlgo);
      }

      this.x509Signer = new MyContentSigner();
    } // constructor

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        outputStream.reset();
        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        byte[] dataToSign = outputStream.toByteArray();
        outputStream.reset();
        return atomicSign(dataToSign);
      }

      @Override
      public byte[] atomicSign(byte[] dataToSign) throws SignatureException {
        try {
          return identity.sign(mechanism, null, dataToSign);
        } catch (TokenException ex) {
          LogUtil.warn(LOG, ex);
          throw new SignatureException("TokenException: " + ex.getMessage());
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }
    }

  } // class Mac

  private static class RSAPkcs1v1_5 extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final byte[] digestPkcsPrefix;

    private final int modulusBitLen;

    private final OutputStream outputStream;

    private final MyContentSigner x509Signer;

    static {
      algoMechMap.put(RSA_SHA1,   CKM_SHA1_RSA_PKCS);
      algoMechMap.put(RSA_SHA224, CKM_SHA224_RSA_PKCS);
      algoMechMap.put(RSA_SHA256, CKM_SHA256_RSA_PKCS);
      algoMechMap.put(RSA_SHA384, CKM_SHA384_RSA_PKCS);
      algoMechMap.put(RSA_SHA512, CKM_SHA512_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_224, CKM_SHA3_224_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_256, CKM_SHA3_256_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_384, CKM_SHA3_384_RSA_PKCS);
      algoMechMap.put(RSA_SHA3_512, CKM_SHA3_512_RSA_PKCS);
    } // method static

    RSAPkcs1v1_5(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);

      if (!signAlgo.isRSAPkcs1SigAlgo()) {
        throw new XiSecurityException("not an RSA PKCS#1 algorithm: " + signAlgo);
      }

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_RSA_PKCS)) {
        mechanism = CKM_RSA_PKCS;
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        mechanism = CKM_RSA_X_509;
      } else if (identity.supportsSign(mech)) {
        mechanism = mech;
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      if (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509) {
        this.digestPkcsPrefix = Pkcs1Util.getDigestPkcsPrefix(signAlgo.hashAlgo());
      } else {
        this.digestPkcsPrefix = null;
      }

      this.modulusBitLen = identity.key().rsaModulus().bitLength();
      this.outputStream = (mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_X_509)
          ? new DigestOutputStream(signAlgo.hashAlgo().createDigest())
          : new ByteArrayOutputStream();

      this.x509Signer = new MyContentSigner();
    } // constructor

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        if (outputStream instanceof ByteArrayOutputStream) {
          ((ByteArrayOutputStream) outputStream).reset();
        } else {
          ((DigestOutputStream) outputStream).reset();
        }
        return outputStream;
      }

      @Override
      public byte[] getSignature() {
        byte[] dataToSign;
        if (outputStream instanceof ByteArrayOutputStream) {
          dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
          ((ByteArrayOutputStream) outputStream).reset();
        } else {
          byte[] hashValue = ((DigestOutputStream) outputStream).digest();
          ((DigestOutputStream) outputStream).reset();
          dataToSign = XiArrays.concatenate(digestPkcsPrefix, hashValue);
        }

        try {
          if (mechanism == CKM_RSA_X_509) {
            dataToSign = Pkcs1Util.EMSA_PKCS1_V1_5_ENCODE(dataToSign, modulusBitLen);
          }

          return identity.sign(mechanism, null, dataToSign);
        } catch (XiSecurityException | TokenException ex) {
          LogUtil.error(LOG, ex, "could not sign");
          throw new IllegalStateException("SignerException: " + ex.getMessage());
        }
      } // method getSignature

      @Override
      public byte[] atomicSign(byte[] dataToSign) throws SignatureException {
        try {
          byte[] dataToHsm;
          if (outputStream instanceof ByteArrayOutputStream) {
            dataToHsm = dataToSign;
          } else {
            HashAlgo hashAlgo = signAlgo.hashAlgo();
            assert hashAlgo != null;
            byte[] hashValue = hashAlgo.hash(dataToSign);
            dataToHsm = XiArrays.concatenate(digestPkcsPrefix, hashValue);
          }

          if (mechanism == CKM_RSA_X_509) {
            dataToHsm = Pkcs1Util.EMSA_PKCS1_V1_5_ENCODE(dataToHsm, modulusBitLen);
          }

          return identity.sign(mechanism, null, dataToHsm);
        } catch (XiSecurityException | TokenException ex) {
          LogUtil.error(LOG, ex, "could not sign");
          throw new SignatureException("SignerException: " + ex.getMessage());
        }
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }

    }

  } // class RSA

  private static class RSAPSS extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    static {
      algoMechMap.put(RSAPSS_SHA1,   CKM_SHA1_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA224, CKM_SHA224_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA256, CKM_SHA256_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA384, CKM_SHA384_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA512, CKM_SHA512_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_224, CKM_SHA3_224_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_256, CKM_SHA3_256_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_384, CKM_SHA3_384_RSA_PKCS_PSS);
      algoMechMap.put(RSAPSS_SHA3_512, CKM_SHA3_512_RSA_PKCS_PSS);
    } // method static

    private final long mechanism;

    private final P11Params.P11RSAPkcsPssParams parameters;

    private final OutputStream outputStream;

    private final MyContentSigner x509Signer;

    RSAPSS(P11Key identity, SignAlgo signAlgo) throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isRSAPSSSigAlgo()) {
        throw new XiSecurityException("not an RSA PSS algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.hashAlgo();

      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      boolean usePss = signAlgo.isRSAPSSMGF1SigAlgo() && identity.supportsSign(CKM_RSA_PKCS_PSS);
      if (usePss) {
        switch (hashAlgo) {
          case SHA1:
          case SHA224:
          case SHA256:
          case SHA384:
          case SHA512:
            break;
          default:
            usePss = false;
        }
      }

      if (usePss) {
        this.mechanism = CKM_RSA_PKCS_PSS;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
      } else if (identity.supportsSign(CKM_RSA_X_509)) {
        this.mechanism = CKM_RSA_X_509;
        this.parameters = null;
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.parameters = new P11Params.P11RSAPkcsPssParams(hashAlgo);
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      if (usePss || identity.supportsSign(CKM_RSA_X_509)) {
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else { // if (identity.supportsSign(mech)) {
        this.outputStream = new ByteArrayOutputStream();
      }
      this.x509Signer = new MyContentSigner();
    } // constructor

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        if (outputStream instanceof ByteArrayOutputStream) {
          ((ByteArrayOutputStream) outputStream).reset();
        } else {
          ((DigestOutputStream) outputStream).reset();
        }

        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        try {
          if (mechanism == CKM_RSA_X_509) {
            HashAlgo hash = signAlgo.hashAlgo();
            assert hash != null;

            byte[] hashValue = ((DigestOutputStream) outputStream).digest();
            byte[] encodedHashValue;
            try {
              encodedHashValue = Pkcs1Util.EMSA_PSS_ENCODE(hash, hashValue, hash, hash.length(),
                  identity.key().rsaModulus().bitLength(), RandomUtil.random());
            } catch (XiSecurityException ex) {
              throw new SignatureException("XiSecurityException: " + ex.getMessage(), ex);
            }
            return identity.sign(mechanism, parameters, encodedHashValue);
          } else {
            byte[] dataToSign;
            if (outputStream instanceof ByteArrayOutputStream) {
              dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
            } else {
              dataToSign = ((DigestOutputStream) outputStream).digest();
            }

            return identity.sign(mechanism, parameters, dataToSign);
          }
        } catch (TokenException ex) {
          LogUtil.warn(LOG, ex, "could not sign");
          throw new SignatureException("SignerException: " + ex.getMessage());
        }
      }// method getSignature

      @Override
      public byte[] atomicSign(byte[] dataToSign) throws SignatureException {
        try {
          if (mechanism == CKM_RSA_X_509) {
            HashAlgo hash = signAlgo.hashAlgo();
            assert hash != null;
            byte[] hashValue = hash.hash(dataToSign);

            byte[] encodedHashValue;
            try {
              encodedHashValue = Pkcs1Util.EMSA_PSS_ENCODE(hash, hashValue, hash, hash.length(),
                  identity.key().rsaModulus().bitLength(), RandomUtil.random());
            } catch (XiSecurityException ex) {
              throw new SignatureException("XiSecurityException: " + ex.getMessage(), ex);
            }
            return identity.sign(mechanism, parameters, encodedHashValue);
          } else {
            byte[] dataToHsm;
            if (outputStream instanceof ByteArrayOutputStream) {
              dataToHsm = dataToSign;
            } else {
              HashAlgo hash = signAlgo.hashAlgo();
              assert hash != null;
              dataToHsm = hash.hash(dataToSign);
            }
            return identity.sign(mechanism, parameters, dataToHsm);
          }
        } catch (TokenException ex) {
          LogUtil.warn(LOG, ex, "could not sign");
          throw new SignatureException("SignerException: " + ex.getMessage());
        }
      }// method atomicSign

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }
    }

  } // class RSAPSS

  private static class SM2 extends P11Signer {

    private static final Map<SignAlgo, Long> algoMechMap = new HashMap<>();

    private final long mechanism;

    private final OutputStream outputStream;

    private final byte[] z;

    private final MyContentSigner x509Signer;

    static {
      algoMechMap.put(SM2_SM3, CKM_VENDOR_SM2_SM3);
    }

    SM2(P11Key identity, SignAlgo signAlgo, BigInteger pubPointX, BigInteger pubPointY)
        throws XiSecurityException {
      super(identity, signAlgo);
      if (!signAlgo.isSM2SigAlgo()) {
        throw new XiSecurityException("not an SM2 algorithm: " + signAlgo);
      }

      HashAlgo hashAlgo = signAlgo.hashAlgo();
      long mech = Optional.ofNullable(algoMechMap.get(signAlgo))
          .orElseThrow(() -> new XiSecurityException(
              "unsupported signature algorithm " + signAlgo));

      if (identity.supportsSign(CKM_VENDOR_SM2)) {
        this.mechanism = CKM_VENDOR_SM2;
        this.z = KeyInfoUtil.getSM2Z(null, pubPointX, pubPointY);
        this.outputStream = new DigestOutputStream(hashAlgo.createDigest());
      } else if (identity.supportsSign(mech)) {
        this.mechanism = mech;
        this.z = null; // not required
        this.outputStream = new ByteArrayOutputStream();
      } else {
        throw new XiSecurityException("signature algorithm " + signAlgo
            + " is not supported by the device");
      }

      this.x509Signer = new MyContentSigner();
    }

    @Override
    public ContentSigner contentSigner() {
      return x509Signer;
    }

    private void reset() {
      if (outputStream instanceof ByteArrayOutputStream) {
        ((ByteArrayOutputStream) outputStream).reset();
      } else {
        ((DigestOutputStream) outputStream).reset();
        try {
          outputStream.write(z, 0, z.length);
        } catch (IOException ex) {
          throw new IllegalStateException(ex.getMessage());
        }
      }
    }

    private class MyContentSigner implements ContentSigner {

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signAlgo.algorithmIdentifier();
      }

      @Override
      public Integer getC509AlgorithmIdentifier() {
        return signAlgo.c509AlgorithmIdentifier();
      }

      @Override
      public OutputStream getOutputStream() {
        reset();
        return outputStream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        try {
          return dsaSigPlainToX962(getPlainSignature());
        } catch (SignatureException ex) {
          LogUtil.warn(LOG, ex);
          throw ex;
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public byte[] atomicSign(byte[] dataToSign) throws SignatureException {
        try {
          return dsaSigPlainToX962(getPlainSignature(dataToSign));
        } catch (SignatureException ex) {
          LogUtil.warn(LOG, ex);
          throw ex;
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public byte[] getC509Signature() throws SignatureException {
        try {
          return getPlainSignature();
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

      @Override
      public byte[] atomicC509Sign(byte[] dataToSign) throws SignatureException {
        try {
          return getPlainSignature(dataToSign);
        } catch (Throwable th) {
          LogUtil.warn(LOG, th);
          throw new SignatureException(th.getClass().getName() + ": " + th.getMessage());
        }
      }

    }

    private byte[] getPlainSignature() throws TokenException {
      byte[] dataToSign = (outputStream instanceof ByteArrayOutputStream)
        // dataToSign is the real message
        ? ((ByteArrayOutputStream) outputStream).toByteArray()
        // dataToSign is Hash(Z||Real Message)
        : ((DigestOutputStream) outputStream).digest();

      reset();

      return identity.sign(mechanism, null, dataToSign);
    }

    private byte[] getPlainSignature(byte[] dataToSign) throws TokenException {
      byte[] dataToHsm;
      if (outputStream instanceof ByteArrayOutputStream) {
        dataToHsm = dataToSign;
      } else {
        HashAlgo hashAlgo = signAlgo.hashAlgo();
        assert hashAlgo != null;
        dataToHsm = hashAlgo.hash(z, dataToSign);
      }

      return identity.sign(mechanism, null, dataToHsm);
    }

  } // class SM2

  private static byte[] dsaSigPlainToX962(byte[] signature) throws SignatureException {
    byte[] x962Sig = Asn1Util.dsaSigPlainToX962(Args.notNull(signature, "signature"));

    if (Arrays.equals(x962Sig, signature)) {
      throw new SignatureException("signature is not correctly encoded.");
    }
    return x962Sig;
  }

}
