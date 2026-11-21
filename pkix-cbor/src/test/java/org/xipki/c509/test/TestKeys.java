// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.crypto.AtomicContentVerifier;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.C509ECSubjectPublicKey;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * Keys, signers and verifiers for the tests, all backed by the {@link CryptoApi} on the class
 * path (crypto-be-jdk).
 *
 * @author Lijun Liao (xipki)
 */
final class TestKeys {

  private static final CryptoApi API = CryptoApiFactory.get();

  /** The signature algorithm to use with a key algorithm. */
  private static final Map<Integer, Integer> SIG_ALG_FOR_KEY = Map.ofEntries(
      Map.entry(ConstPublicKeyAlgorithm.ec_secp256r1, ConstSignatureAlgorithm.ecdsa_with_SHA256),
      Map.entry(ConstPublicKeyAlgorithm.ec_brainpoolP256r1,
          ConstSignatureAlgorithm.ecdsa_with_SHA256),
      Map.entry(ConstPublicKeyAlgorithm.ec_frp256v1, ConstSignatureAlgorithm.ecdsa_with_SHA256),
      Map.entry(ConstPublicKeyAlgorithm.ec_secp384r1, ConstSignatureAlgorithm.ecdsa_with_SHA384),
      Map.entry(ConstPublicKeyAlgorithm.ec_brainpoolP384r1,
          ConstSignatureAlgorithm.ecdsa_with_SHA384),
      Map.entry(ConstPublicKeyAlgorithm.ec_secp521r1, ConstSignatureAlgorithm.ecdsa_with_SHA512),
      Map.entry(ConstPublicKeyAlgorithm.ec_brainpoolP512r1,
          ConstSignatureAlgorithm.ecdsa_with_SHA512),
      Map.entry(ConstPublicKeyAlgorithm.ec_sm2p256v1, ConstSignatureAlgorithm.sm2_with_sm3),
      Map.entry(ConstPublicKeyAlgorithm.ed25519, ConstSignatureAlgorithm.ed25519),
      Map.entry(ConstPublicKeyAlgorithm.ed448, ConstSignatureAlgorithm.ed448),
      Map.entry(ConstPublicKeyAlgorithm.rsaEncryption,
          ConstSignatureAlgorithm.sha256WithRSAEncryption),
      Map.entry(ConstPublicKeyAlgorithm.ML_DSA_44, ConstSignatureAlgorithm.ML_DSA_44),
      Map.entry(ConstPublicKeyAlgorithm.ML_DSA_65, ConstSignatureAlgorithm.ML_DSA_65),
      Map.entry(ConstPublicKeyAlgorithm.ML_DSA_87, ConstSignatureAlgorithm.ML_DSA_87));

  static class MyContentVerifierFactory implements ContentVerifierFactory {

    private final PublicKey publicKey;

    MyContentVerifierFactory(PublicKey publicKey) {
      this.publicKey = publicKey;
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
      throw new UnsupportedOperationException("unsupported");
    }

    @Override
    public AtomicContentVerifier getForC509(int verifierAlgorithmIdentifier)
        throws GenerationException {
      return new AtomicContentVerifier() {
        @Override
        public AlgorithmIdentifier x509Algorithm() {
          throw new UnsupportedOperationException("unsupported");
        }

        @Override
        public boolean atomicX509Verify(byte[] dataToVerify, byte[] signature)
            throws SignatureException {
          throw new UnsupportedOperationException("unsupported");
        }

        @Override
        public int c509Algorithm() {
          return verifierAlgorithmIdentifier;
        }

        @Override
        public boolean atomicC509Verify(byte[] dataToVerify, SignatureValue signature)
            throws SignatureException {
          if (!(signature instanceof BytesSignatureValue)) {
            throw new SignatureException("unsupported signature value " + signature.getClass());
          }
          byte[] value = ((BytesSignatureValue) signature).value();
          if (verifierAlgorithmIdentifier == ConstSignatureAlgorithm.unsigned) {
            return value.length == 0;
          }
          if (ConstSignatureAlgorithm.isEcdsaSignature(verifierAlgorithmIdentifier)) {
            value = Asn1Util.dsaSigPlainToX962(value);
          }
          try {
            Signature sig = jcaSignature(verifierAlgorithmIdentifier);
            sig.initVerify(publicKey);
            sig.update(dataToVerify);
            return sig.verify(value);
          } catch (GeneralSecurityException e) {
            throw new SignatureException("could not verify", e);
          }
        }
      };
    }
  }

  private TestKeys() {
  }

  static int signatureAlgorithmFor(int keyAlgorithm) {
    Integer alg = SIG_ALG_FOR_KEY.get(keyAlgorithm);
    if (alg == null) {
      throw new IllegalArgumentException("no signature algorithm for "
          + ConstPublicKeyAlgorithm.describe(keyAlgorithm));
    }
    return alg;
  }

  static C509KeyPair generate(int keyAlgorithm) throws GeneralSecurityException {
    return generate(keyAlgorithm, false);
  }

  /**
   * @param compressed for EC keys: whether to use the compressed point form.
   */
  static C509KeyPair generate(int keyAlgorithm, boolean compressed)
      throws GeneralSecurityException {
    KeySpec spec = KeySpec.ofC509AlgorithmIdentifier(keyAlgorithm);
    if (spec == null) {
      throw new NoSuchAlgorithmException("unsupported key algorithm "
          + ConstPublicKeyAlgorithm.describe(keyAlgorithm));
    }
    return wrap(KeyInfoUtil.generateKeyPair(spec), compressed);
  }

  static C509KeyPair generateRsa(int bits, BigInteger publicExponent)
      throws GeneralSecurityException {
    KeyPairGenerator gen = API.newKeyPairGenerator("RSA");
    gen.initialize(new RSAKeyGenParameterSpec(bits, publicExponent), API.getSecureRandom());
    return wrap(gen.generateKeyPair(), false);
  }

  private static C509KeyPair wrap(KeyPair kp, boolean compressed)
      throws InvalidKeySpecException {
    SubjectPublicKeyInfo spki;
    try {
      spki = SubjectPublicKeyInfo.fromPublicKey(kp.getPublic());
    } catch (CodecException e) {
      throw new InvalidKeySpecException(e);
    }

    C509SubjectPublicKey key = C509SubjectPublicKey.fromSubjectPublicKeyInfo(spki);
    if (key instanceof C509ECSubjectPublicKey) {
      byte[] point = spki.getSubjectPublicKey().getOctets();
      if (compressed) {
        // 04 || X || Y  ->  02/03 || X
        byte[] c = Arrays.copyOf(point, 1 + (point.length - 1) / 2);
        c[0] = ((point[point.length - 1] & 1) == 1)
            ? C509ECSubjectPublicKey.COMPRESSED_ODD_Y : C509ECSubjectPublicKey.COMPRESSED_EVEN_Y;
        point = c;
      }
      key = new C509ECSubjectPublicKey(key.algorithm(), point);
    }
    return new C509KeyPair(kp.getPrivate(), kp.getPublic(), key);
  }

  /**
   * Converts a C509 public key into a JCA key. In contrast to
   * {@link C509SubjectPublicKey#publicKey()} this handles all curves of the backend and
   * compressed points.
   */
  static PublicKey toJca(C509SubjectPublicKey key) throws InvalidKeySpecException {
    SubjectPublicKeyInfo spki = key.toX509SubjectPublicKey();
    if (key instanceof C509ECSubjectPublicKey) {
      byte[] point = spki.getSubjectPublicKey().getOctets();
      if (point[0] != C509ECSubjectPublicKey.UNCOMPRESSED) {
        point = API.getByOID(ConstPublicKeyAlgorithm.curveOidForCode(key.algorithm()))
            .getCurve().decodePoint(point).getEncoded(false);
        spki = new SubjectPublicKeyInfo(spki.getAlgorithm(), point);
      }
    }
    return API.getPublicKey(spki);
  }

  static AtomicContentSigner contentSigner(int algorithm, PrivateKey key) {
    return new AtomicContentSigner() {

      @Override
      public AlgorithmIdentifier x509Algorithm() {
        throw new UnsupportedOperationException("unsupported");
      }

      @Override
      public byte[] atomicX509Sign(byte[] dataToSign) throws SignatureException {
        throw new UnsupportedOperationException("unsupported");
      }

      @Override
      public int c509Algorithm() {
        return algorithm;
      }

      @Override
      public SignatureValue atomicC509Sign(byte[] dataToSign) throws SignatureException {
        if (algorithm == ConstSignatureAlgorithm.unsigned) {
          return new BytesSignatureValue(new byte[0]);
        }
        try {
          Signature sig = jcaSignature(algorithm);
          sig.initSign(key, API.getSecureRandom());
          sig.update(dataToSign);
          byte[] value = sig.sign();
          if (ConstSignatureAlgorithm.isEcdsaSignature(algorithm)) {
            int len = (((ECKey) key).getParams().getOrder().bitLength() + 7) / 8;
            value = Asn1Util.dsaSigX962ToPlain(value, len);
          }
          return new BytesSignatureValue(value);
        } catch (GeneralSecurityException e) {
          throw new SignatureException("could not sign", e);
        }
      }
    };
  }

  static C509ExtendedSigner signer(int algorithm, PrivateKey key) {
    return signer(algorithm, key, null);
  }

  static C509ExtendedSigner signer(
      int algorithm, PrivateKey key, CoseC509 certs) {
    return new C509ExtendedSigner() {
      @Override
      public byte[] certHash(int c509HashAlg) {
        HashAlgo hashAlgo;
        try {
          hashAlgo = HashAlgo.getInstanceForC509Alg(c509HashAlg);
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return hashAlgo.hash(certs.first().getEncoded());
      }

      @Override
      public int c509Algorithm() {
        return algorithm;
      }

      @Override
      public CoseC509 certificates() {
        return certs;
      }

      @Override
      public SignatureValue c509Sign(byte[] tbs) throws SignatureException {
        if (algorithm == ConstSignatureAlgorithm.unsigned) {
          return new BytesSignatureValue(new byte[0]);
        }
        try {
          Signature sig = jcaSignature(algorithm);
          sig.initSign(key, API.getSecureRandom());
          sig.update(tbs);
          byte[] value = sig.sign();
          if (ConstSignatureAlgorithm.isEcdsaSignature(algorithm)) {
            int len = (((ECKey) key).getParams().getOrder().bitLength() + 7) / 8;
            value = Asn1Util.dsaSigX962ToPlain(value, len);
          }
          return new BytesSignatureValue(value);
        } catch (GeneralSecurityException e) {
          throw new SignatureException("could not sign", e);
        }
      }
    };
  }

  private static boolean verify(
      int algorithm, PublicKey key, byte[] data,
      SignatureValue signature) throws SignatureException {
    if (!(signature instanceof BytesSignatureValue)) {
      throw new SignatureException("unsupported signature value " + signature.getClass());
    }
    byte[] value = ((BytesSignatureValue) signature).value();
    if (algorithm == ConstSignatureAlgorithm.unsigned) {
      return value.length == 0;
    }
    if (ConstSignatureAlgorithm.isEcdsaSignature(algorithm)) {
      value = Asn1Util.dsaSigPlainToX962(value);
    }
    try {
      Signature sig = jcaSignature(algorithm);
      sig.initVerify(key);
      sig.update(data);
      return sig.verify(value);
    } catch (GeneralSecurityException e) {
      throw new SignatureException("could not verify", e);
    }
  }

  private static Signature jcaSignature(int algorithm) throws GeneralSecurityException {
    return SignAlgo.ofC509AlgorithmIdentifier(algorithm).newSignature();
  }

}
