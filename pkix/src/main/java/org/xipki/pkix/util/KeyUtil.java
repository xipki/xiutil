// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.KeyPurposeOIDs;
import org.xipki.codec.util.XiArrays;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.ExtendedKeyUsage;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.KeyUsage;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPrivateKey;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeMLKEMPrivateKey;
import org.xipki.crypto.core.composite.CompositeMLKEMPublicKey;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.KeyStoreWrapper;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.P12ContentSignerBuilder;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.pkcs12.Pkcs12KeyStoreWrapper;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.UnsignedSigner;
import org.xipki.pkix.verify.CompositeMLDSAContentVerifierProvider;
import org.xipki.pkix.verify.KEMContentVerifierProvider;
import org.xipki.pkix.verify.SignatureContentVerifierProvider;
import org.xipki.pkix.verify.XDHContentVerifierProvider;
import org.xipki.util.misc.RandomUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;

/**
 * Key Util.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyUtil {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  public static final AlgorithmIdentifier ALGID_RSA =
      AlgorithmIdentifier.ofNullParams(AlgorithmOIDs.id_rsaEncryption);

  private static final BigInteger SM2_ORDER = new BigInteger(
      "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);

  private KeyUtil() {
  }

  public static Pkcs12KeyStore loadPKCS12KeyStore(InputStream is, char[] password)
      throws XiSecurityException {
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    try {
      ks.load(is, password);
    } catch (IOException e) {
      throw new XiSecurityException(e);
    }
    return ks;
  }

  public static Pkcs12KeyStore loadPKCS12KeyStore(byte[] bytes, char[] password)
      throws XiSecurityException {
    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    try {
      ks.load(bytes, password);
    } catch (IOException e) {
      throw new XiSecurityException(e);
    }
    return ks;
  }

  /**
   * Loads the keystore of the JDK, e.g. JCEKS or JKS. The PKCS#12 keystores are loaded by
   * {@link #loadPKCS12KeyStore(InputStream, char[])}.
   * @param storeType the keystore type, e.g. "JCEKS".
   * @param is the input stream of the keystore, or null to create an empty one.
   * @param password the password of the keystore.
   * @return the keystore.
   * @throws XiSecurityException if the keystore cannot be loaded, or is of type PKCS#12.
   */
  public static KeyStore loadKeyStore(String storeType, InputStream is, char[] password)
      throws XiSecurityException {
    if ("PKCS12".equalsIgnoreCase(storeType) || "PKCS#12".equalsIgnoreCase(storeType)) {
      throw new XiSecurityException(
          "PKCS#12 keystore is not supported here, use loadPKCS12KeyStore instead");
    }

    KeyStore keystore;
    try {
      keystore = KeyStore.getInstance(storeType);
    } catch (KeyStoreException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    try {
      keystore.load(is, password);
      return keystore;
    } catch (NoSuchAlgorithmException | ClassCastException
             | CertificateException | IOException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  }

  /**
   * Generates a key pair with the random of the crypto backend.
   * @param keySpec the key spec.
   * @return the key pair.
   */
  public static KeyPair generateKeyPair(KeySpec keySpec)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    SecureRandom random = cryptoApi.getSecureRandom();
    switch (keySpec) {
      case RSA2048:
      case RSA3072:
      case RSA4096: {
        KeyPairGenerator kpGen = getKeyPairGenerator("RSA");
        Integer i = keySpec.RSAKeyBitSize();
        assert i != null;
        int keyBitSize = i;
        kpGen.initialize(keyBitSize, random);
        return kpGen.generateKeyPair();
      }
      case ED25519:
      case ED448:
      case X25519:
      case X448: {
        String algorithm = keySpec == KeySpec.ED25519 ? "ED25519"
            : keySpec == KeySpec.ED448  ? "ED448"
            : keySpec == KeySpec.X25519 ? "X25519" : "X448";

        // 255 for Curve25519: accepted by both the JDK and BouncyCastle
        int keyBitSize = keySpec == KeySpec.ED25519 ? 255
            : keySpec == KeySpec.ED448  ? 448
            : keySpec == KeySpec.X25519 ? 255 : 448;

        KeyPairGenerator kpGen = getKeyPairGenerator(algorithm);
        kpGen.initialize(keyBitSize, random);
        return kpGen.generateKeyPair();
      }
      case MLDSA44:
      case MLDSA65:
      case MLDSA87: {
        MldsaVariant spec =
              (keySpec == KeySpec.MLDSA44)  ? MldsaVariant.ml_dsa_44
            : (keySpec == KeySpec.MLDSA65)  ? MldsaVariant.ml_dsa_65
            : MldsaVariant.ml_dsa_87;
        return cryptoApi.generateKeyPair(spec);
      }
      case MLKEM512:
      case MLKEM768:
      case MLKEM1024: {
        MlkemVariant spec =
              (keySpec == KeySpec.MLKEM512) ? MlkemVariant.ml_kem_512
            : (keySpec == KeySpec.MLKEM768) ? MlkemVariant.ml_kem_768
            : MlkemVariant.ml_kem_1024;
        return cryptoApi.generateKeyPair(spec);
      }
      case P256:
      case P384:
      case P521:
      case BRAINPOOLP256R1:
      case BRAINPOOLP384R1:
      case BRAINPOOLP512R1:
      case SM2: {
        EcCurveEnum curve = keySpec.ecCurve();
        assert curve != null;
        ECGenParameterSpec spec = new ECGenParameterSpec(curve.oid().getId());
        KeyPairGenerator kpGen = getKeyPairGenerator("EC");
        kpGen.initialize(spec, random);
        return kpGen.generateKeyPair();
      }
    }

    if (keySpec.isCompositeMLDSA()) {
      KeyPair pqcKeyPair = generateKeyPair(keySpec.compositePqcVariant());
      KeyPair tradKeyPair = generateKeyPair(keySpec.compositeTradVariant());
      CompositeMLDSAPrivateKey sk;
      try {
        sk = new CompositeMLDSAPrivateKey(pqcKeyPair.getPrivate(), tradKeyPair.getPrivate());
      } catch (CodecException e) {
        throw new InvalidAlgorithmParameterException(e);
      }

      CompositeMLDSAPublicKey pk = new CompositeMLDSAPublicKey(
          pqcKeyPair.getPublic(), tradKeyPair.getPublic());
      return new KeyPair(pk, sk);
    } else if (keySpec.isCompositeMLKEM()) {
      KeyPair pqcKeyPair = generateKeyPair(keySpec.compositePqcVariant());
      KeyPair tradKeyPair = generateKeyPair(keySpec.compositeTradVariant());
      CompositeMLKEMPrivateKey sk = new CompositeMLKEMPrivateKey(
          pqcKeyPair.getPrivate(), tradKeyPair.getPrivate());
      CompositeMLKEMPublicKey pk = new CompositeMLKEMPublicKey(
          pqcKeyPair.getPublic(), tradKeyPair.getPublic());
      return new KeyPair(pk, sk);
    }

    throw new IllegalStateException("unknown keyspec " + keySpec);
  }

  public static KeyPairWithSubjectPublicKeyInfo generateKeyPair2(KeySpec keySpec)
      throws Exception {
    KeyPair keypair = generateKeyPair(keySpec);
    SubjectPublicKeyInfo pkInfo = KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
    return new KeyPairWithSubjectPublicKeyInfo(keypair, pkInfo);
  }

  public static Pkcs12KeyStoreWrapper generateKeyPair3(
      KeySpec keySpec, KeystoreGenerationParameters params) throws Exception {
    KeyPairWithSubjectPublicKeyInfo kp = generateKeyPair2(keySpec);

    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    Instant notAfter = notBefore.plus(3650, ChronoUnit.DAYS);

    String dnStr = "CN=DUMMY";
    X500Name subjectDn = new X500Name(dnStr);
    SubjectPublicKeyInfo subjectPublicKeyInfo = kp.subjectPublicKeyInfo();
    Signer signer;
    if (params.unsigned() != null && params.unsigned()) {
      signer = UnsignedSigner.INSTANCE;
    } else {
      signer = getSigner(kp.keypair().getPrivate(), kp.keypair().getPublic(), true);
    }

    // Generate keystore
    Certificate.V3CertBuilder certGenerator = new Certificate.V3CertBuilder(
        subjectDn, BigInteger.ONE, notBefore, notAfter, subjectDn, subjectPublicKeyInfo);

    byte[] encodedPkData = kp.subjectPublicKeyInfo().subjectPublicKey();
    byte[] skiValue = HashAlgo.SHA1.hash(encodedPkData);
    certGenerator.addExtension(Extension.ofSubjectKeyIdentifier(false, skiValue));
    certGenerator.addExtension(Extension.ofBasicConstraints(true, new BasicConstraints(false)));
    certGenerator.addExtension(Extension.ofKeyUsage(true, KeyUsage.digitalSignature));
    certGenerator.addExtension(Extension.ofExtendedKeyUsage(false,
        new ExtendedKeyUsage(KeyPurposeOIDs.id_kp_clientAuth, KeyPurposeOIDs.id_kp_serverAuth)));

    Certificate cert = certGenerator.build(signer.x509Signer());

    Pkcs12KeyStore ks = new Pkcs12KeyStore();
    ks.load((byte[]) null, params.password());

    ks.setKeyEntry("main", PrivateKeyInfo.fromPrivateKey(kp.keypair().getPrivate()), cert);

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    Pkcs12KeyStoreWrapper result = new Pkcs12KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    result.setSubjectPublicKeyInfo(kp.subjectPublicKeyInfo());
    return result;
  } // method generateKeyPair3

  public static KeyStoreWrapper generateSecretKey(
      String algorithm, int keyBitLen, KeystoreGenerationParameters params) throws Exception {
    if (keyBitLen % 8 != 0) {
      throw new IllegalArgumentException("keyBitLen (" + keyBitLen + ") must be multiple of 8");
    }

    byte[] keyValue = RandomUtil.nextBytes(keyBitLen / 8);

    SecretKey secretKey = new SecretKeySpec(keyValue, algorithm);

    KeyStore ks = KeyUtil.loadKeyStore("JCEKS", null, params.password());
    ks.setKeyEntry("main", secretKey, params.password(), null);
    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    KeyStoreWrapper result = new KeyStoreWrapper(ksStream.toByteArray());
    result.setKeystoreObject(ks);
    return result;
  }

  private static KeyPairGenerator getKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    String upperAlg = algorithm.toUpperCase(Locale.ROOT);
    if ("ECDSA".equals(upperAlg)) {
      algorithm = "EC";
    }

    return cryptoApi.newKeyPairGenerator(algorithm);
  } // method getKeyPairGenerator

  public static RSAPublicKey getRSAPublicKey(RSAPublicKeySpec keySpec)
      throws InvalidKeySpecException {
    Args.notNull(keySpec, "keySpec");
    try {
      return (RSAPublicKey) cryptoApi.newKeyFactory("RSA").generatePublic(keySpec);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new InvalidKeySpecException("could not find KeyFactory for RSA: " + ex.getMessage());
    }
  }

  /**
   * Initializes the signature for signing, with the random of the crypto backend.
   * @param sig the signature.
   * @param key the private key.
   */
  public static void initSign(Signature sig, PrivateKey key) throws InvalidKeyException {
    sig.initSign(key, cryptoApi.getSecureRandom());
  }

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    Args.notNull(publicKey, "publicKey");

    if (publicKey instanceof RSAPublicKey) {
      RSAPublicKey rsaPubKey = (RSAPublicKey) publicKey;
      return new SubjectPublicKeyInfo(ALGID_RSA,
          new org.xipki.codec.asn1.crypto.RSAPublicKey(rsaPubKey.getModulus(),
              rsaPubKey.getPublicExponent()));
    } else if (publicKey instanceof ECPublicKey) {
      ECPublicKey ecPubKey = (ECPublicKey) publicKey;

      ECParameterSpec paramSpec = ecPubKey.getParams();
      Asn1Oid curveOid = detectCurveOid(paramSpec);

      ECPoint pointW = ecPubKey.getW();
      BigInteger wx = pointW.getAffineX();
      if (wx.signum() != 1) {
        throw new InvalidKeyException("Wx is not positive");
      }

      BigInteger wy = pointW.getAffineY();
      if (wy.signum() != 1) {
        throw new InvalidKeyException("Wy is not positive");
      }

      int keysize = (paramSpec.getCurve().getField().getFieldSize() + 7) / 8;
      byte[] wxBytes = BigIntegers.asUnsignedByteArray(keysize, wx);
      byte[] wyBytes = BigIntegers.asUnsignedByteArray(keysize, wy);
      byte[] pubKey = XiArrays.concatenate(new byte[]{4}, wxBytes, wyBytes);
      AlgorithmIdentifier algId = new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, curveOid);
      return new SubjectPublicKeyInfo(algId, pubKey);
    } else {
      try {
        return SubjectPublicKeyInfo.fromPublicKey(publicKey);
      } catch (CodecException e) {
        throw new InvalidKeyException("could not parse encoded PublicKey", e);
      }
    }
  } // method createSubjectPublicKeyInfo

  public static ECPublicKey createECPublicKey(EcCurveEnum curve, byte[] encodedPoint)
      throws InvalidKeySpecException {
    return (ECPublicKey) KeyInfoUtil.getPublicKey(
        new SubjectPublicKeyInfo(curve.algId(), encodedPoint));
  }

  public static Asn1Oid detectCurveOid(ECParameterSpec paramSpec) {
    byte[] ecParams = Optional.ofNullable(
        Functions.getEcParams(paramSpec.getOrder(), paramSpec.getGenerator().getAffineX()))
        .orElseThrow(() -> new IllegalArgumentException("unknown paramSpec"));

    try {
      return Asn1Oid.fromEncoded(ecParams);
    } catch (CodecException e) {
      throw new IllegalArgumentException("ecParams is not a valid OID " + Hex.encode(ecParams));
    }
  }

  public static ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    return getContentVerifierProvider(publicKey, null, null);
  }

  public static ContentVerifierProvider getContentVerifierProvider(
      PublicKey publicKey, DHSigStaticKeyCertPair ownerKeyAndCert, SecretKey ownerMasterKey)
      throws InvalidKeyException {
    Args.notNull(publicKey, "publicKey");

    // Detect the key type by the algorithm OID, not by PublicKey.getAlgorithm(): the providers
    // return different names, e.g. the JDK "XDH" for X25519 and X448, and "ML-KEM" for all
    // ML-KEM parameter sets.
    AlgorithmIdentifier algId;
    try {
      algId = SubjectPublicKeyInfo.algorithmFromPublicKey(publicKey);
    } catch (CodecException e) {
      throw new InvalidKeyException("could not parse encoded PublicKey", e);
    }

    KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(algId);
    if (keySpec != null) {
      if (keySpec.isMontgomeryEC()) {
        // X25519, X448
        if (ownerKeyAndCert == null) {
          throw new InvalidKeyException("ownerKeyAndCert is required but absent");
        }
        return new XDHContentVerifierProvider(publicKey, ownerKeyAndCert);
      } else if (keySpec.isMlkem() || keySpec.isCompositeMLKEM()) {
        if (ownerMasterKey == null) {
          throw new InvalidKeyException("ownerMasterKey is required but absent");
        }
        return new KEMContentVerifierProvider(publicKey, ownerMasterKey);
      } else if (keySpec.isCompositeMLDSA() && publicKey instanceof CompositeMLDSAPublicKey) {
        return new CompositeMLDSAContentVerifierProvider((CompositeMLDSAPublicKey) publicKey);
      }
    }

    return new SignatureContentVerifierProvider(publicKey);
  } // method getContentVerifierProvider

  public static Signer getSigner(PrivateKey key, PublicKey publicKey) throws Exception {
    return getSigner(key, publicKey, false);
  }

  public static Signer getSigner(PrivateKey key, PublicKey publicKey, boolean allowUnsigned)
      throws Exception {
    SignAlgo algo;
    if (key instanceof RSAPrivateKey) {
      algo = SignAlgo.RSAPSS_SHA256;
    } else if (key instanceof ECPrivateKey) {
      BigInteger order = ((ECPrivateKey) key).getParams().getOrder();
      if (SM2_ORDER.equals(order)) {
        algo = SignAlgo.SM2_SM3;
      } else {
        int orderBitLength = order.bitLength();
        algo = orderBitLength > 384 ? SignAlgo.ECDSA_SHA512
            :  orderBitLength > 256 ? SignAlgo.ECDSA_SHA384
            :  orderBitLength > 160 ? SignAlgo.ECDSA_SHA256 :  SignAlgo.ECDSA_SHA1;
      }
    } else {
      byte[] encodedPublicKey = publicKey.getEncoded();
      AlgorithmIdentifier pkAlgId = SubjectPublicKeyInfo.algorithmFromEncoded(encodedPublicKey);
      algo = SignAlgo.ofAlgorithmIdentifier(pkAlgId);
      if (algo == null) {
        KeySpec keySpec = KeySpec.ofPublicKey(SubjectPublicKeyInfo.fromEncoded(encodedPublicKey));
        if (keySpec == null) {
          throw new IllegalArgumentException(
              "unknown public key algorithm " + pkAlgId.getAlgorithm());
        }

        if (keySpec.isEdwardsEC()) {
          algo = (keySpec == KeySpec.ED25519) ? SignAlgo.ED25519 : SignAlgo.ED448;
        } else if (keySpec == KeySpec.MLDSA44) {
          algo = SignAlgo.MLDSA44;
        } else if (keySpec == KeySpec.MLDSA65) {
          algo = SignAlgo.MLDSA65;
        } else if (keySpec == KeySpec.MLDSA87) {
          algo = SignAlgo.MLDSA87;
        } else if (keySpec.isCompositeMLDSA()) {
          algo = SignAlgo.ofAlgorithmIdentifier(keySpec.algorithmIdentifier());
        } else if (allowUnsigned & (keySpec.isMontgomeryEC() ||
            keySpec.isMlkem() || keySpec.isCompositeMLKEM())) {
          return UnsignedSigner.INSTANCE;
        } else {
          throw new IllegalArgumentException("unknown key-spec " + keySpec);
        }
      }
    }

    P12ContentSignerBuilder builder = new P12ContentSignerBuilder(key, publicKey);
    ConcurrentSigner csigner = builder.createSigner(algo, 1);
    return csigner.borrowSigner();
  } // method getContentSigner

}
