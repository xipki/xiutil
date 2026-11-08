// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.ExtendedKeyUsage;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.KeyUsage;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.KeyPurposeOIDs;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.P12ContentSignerBuilder;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.pkcs12.Pkcs12KeyStoreWrapper;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.UnsignedSigner;
import org.xipki.pkix.verify.CompositeMLDSAContentVerifierProvider;
import org.xipki.pkix.verify.KEMContentVerifierProvider;
import org.xipki.pkix.verify.SignatureContentVerifierProvider;
import org.xipki.pkix.verify.XDHContentVerifierProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import javax.crypto.SecretKey;

/**
 * Key Util for X.509 structures, and for the keystores with X.509 certificates.
 *
 * @author Lijun Liao (xipki)
 */
public class X509KeyUtil {

  private static final BigInteger SM2_ORDER = new BigInteger(
      "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);

  private X509KeyUtil() {
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

  public static KeyPairWithSubjectPublicKeyInfo generateKeyPair2(KeySpec keySpec)
      throws Exception {
    KeyPair keypair = KeyUtil.generateKeyPair(keySpec);
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

    Certificate cert = certGenerator.build(signer.contentSigner());

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
