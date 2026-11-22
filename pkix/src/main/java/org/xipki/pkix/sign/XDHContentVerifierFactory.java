// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.asn1.crmf.DhSigStatic;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.C509DhSigStaticSignatureValue;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.crypto.core.EcCurveEnum;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.time.Instant;
import java.util.Arrays;

/**
 * Content verifier factory for the proof-of-possession of Diffie-Hellman keys as defined in
 * RFC 6955 (static DH, the signature is a MAC):
 * <ul>
 *   <li>X25519 and X448 keys: the XiPKI own algorithms DHPOP-X25519 and DHPOP-X448, for X.509
 *       and C509.</li>
 *   <li>EC keys: the C509 algorithms sa-ecdhPop-sha256-hmac-sha256,
 *       sa-ecdhPop-sha384-hmac-sha384 and sa-ecdhPop-sha512-hmac-sha512.</li>
 * </ul>
 * The MAC key is K = Hash(LeadingInfo || ZZ || TrailingInfo), where ZZ is the shared secret,
 * LeadingInfo the encoded subject and TrailingInfo the encoded issuer of the owner's
 * certificate. For a C509 certificate without issuer, the issuer is the subject.
 *
 * @author Lijun Liao (xipki)
 */
public class XDHContentVerifierFactory implements ContentVerifierFactory {

  private static class XDHContentVerifier implements ContentVerifier {

    private class MacOutputStream extends OutputStream {

      @Override
      public void write(int bb) throws IOException {
        mac.update((byte) bb);
      }

      @Override
      public void write(byte[] bytes) throws IOException {
        mac.update(bytes, 0, bytes.length);
      }

      @Override
      public void write(byte[] bytes, int off, int len) throws IOException {
        mac.update(bytes, off, len);
      }

    } // class MacOutputStream

    private final AlgorithmIdentifier algId;

    private final Integer c509AlgId;

    private final MacOutputStream outputStream;

    private final Mac mac;

    private final SecretKey macKey;

    private final DHSigStaticKeyCertPair ownerKeyAndCert;

    private XDHContentVerifier(AlgorithmIdentifier algId, Integer c509AlgId,
                               Mac mac, SecretKey macKey, DHSigStaticKeyCertPair ownerKeyAndCert) {
      this.algId = algId;
      this.c509AlgId = c509AlgId;
      this.mac = mac;
      this.macKey = macKey;
      this.ownerKeyAndCert = ownerKeyAndCert;
      this.outputStream = new MacOutputStream();
    }

    @Override
    public AlgorithmIdentifier x509Algorithm() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      try {
        mac.init(macKey);
      } catch (InvalidKeyException ex) {
        throw new IllegalStateException("could not init MAC: " + ex.getMessage());
      }
      return outputStream;
    }

    @Override
    public boolean x509Verify(byte[] expected) {
      byte[] expectedHashValue;
      try {
        expectedHashValue = DhSigStatic.fromEncoded(expected).hashValue();
      } catch (CodecException e) {
        return false;
      }
      return MessageDigest.isEqual(expectedHashValue, mac.doFinal());
    }

    @Override
    public int c509Algorithm() {
      if (c509AlgId != null) {
        return c509AlgId;
      }
      return ContentSigner.checkC509AlgId(null, algId.getAlgorithm());
    }

    @Override
    public boolean c509Verify(SignatureValue signature) throws SignatureException {
      byte[] expectedHashValue = c509HashValue(signature);
      return expectedHashValue != null && MessageDigest.isEqual(expectedHashValue, mac.doFinal());
    }

    @Override
    public boolean atomicC509Verify(byte[] dataToVerify, SignatureValue signature)
        throws SignatureException {
      byte[] expectedHashValue = c509HashValue(signature);
      if (expectedHashValue == null) {
        return false;
      }

      try {
        mac.init(macKey);
      } catch (InvalidKeyException ex) {
        throw new SignatureException("could not init MAC: " + ex.getMessage(), ex);
      }
      mac.update(dataToVerify);
      return MessageDigest.isEqual(expectedHashValue, mac.doFinal());
    }

    /**
     * Returns the hash value of the C509 signature value, or {@code null} if the issuer and
     * serial number in the signature value do not identify the owner's certificate.
     */
    private byte[] c509HashValue(SignatureValue signature) throws SignatureException {
      if (signature instanceof BytesSignatureValue) {
        return ((BytesSignatureValue) signature).value();
      } else if (signature instanceof C509DhSigStaticSignatureValue) {
        C509DhSigStaticSignatureValue sig = (C509DhSigStaticSignatureValue) signature;
        if (sig.hasIssuerAndSerialNumber()) {
          if (!ownerKeyAndCert.serialNumber().equals(sig.serialNumber())
              || !Arrays.equals(ownerKeyAndCert.encodedIssuer(), sig.issuer().getEncoded())) {
            return null;
          }
        }
        return sig.hashValue();
      } else {
        throw new SignatureException("unsupported signature value " + signature.getClass());
      }
    }

  } // class XDHContentVerifier

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final DHSigStaticKeyCertPair ownerKeyAndCert;

  private final byte[] zz;

  /**
   * DHPOP-X25519 or DHPOP-X448 for X25519 and X448 keys, {@code null} for EC keys.
   */
  private final SignAlgo xdhSigAlg;

  public XDHContentVerifierFactory(PublicKey verifyKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    this.ownerKeyAndCert = Args.notNull(ownerKeyAndCert, "ownerKeyAndCert");
    Args.notNull(verifyKey, "verifyKey");
    // by the algorithm OID: PublicKey.getAlgorithm() is provider-specific
    // (e.g. the JDK returns "XDH" for X25519 and X448)
    EcCurveEnum curveEnum = KeyInfoUtil.getCurve(verifyKey);
    String keyAgreementAlg;
    if (EcCurveEnum.X25519 == curveEnum) {
      this.xdhSigAlg = SignAlgo.DHPOP_X25519;
      keyAgreementAlg = curveEnum.name();
    } else if (EcCurveEnum.X448 == curveEnum) {
      this.xdhSigAlg = SignAlgo.DHPOP_X448;
      keyAgreementAlg = curveEnum.name();
    } else if (curveEnum != null && verifyKey instanceof ECKey) {
      this.xdhSigAlg = null;
      keyAgreementAlg = "ECDH";
    } else {
      String keyAlgName = (curveEnum == null) ? verifyKey.getAlgorithm() : curveEnum.name();
      throw new InvalidKeyException("unsupported verifyKey.getAlgorithm(): " + keyAlgName);
    }

    PrivateKey ownerKey = ownerKeyAndCert.privateKey();
    if (curveEnum != KeyInfoUtil.getCurve(ownerKey)) {
      throw new InvalidKeyException("verifyKey and ownerKeyAndCert does not match");
    }

    // compute the shared secret
    try {
      KeyAgreement keyAgreement = cryptoApi.newKeyAgreement(keyAgreementAlg);
      keyAgreement.init(ownerKey);
      keyAgreement.doPhase(verifyKey, true);
      this.zz = keyAgreement.generateSecret();
    } catch (GeneralSecurityException | RuntimeException ex) {
      throw new InvalidKeyException("KeyChange error", ex);
    }
  } // constructor

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
    boolean matchOid = xdhSigAlg != null && xdhSigAlg.algorithmIdentifier() != null
        && xdhSigAlg.algorithmIdentifier().getAlgorithm().equals(oid);

    if (!matchOid) {
      throw new GenerationException(
          "given public key is not suitable for the algorithm " + oid.getId());
    }

    return newVerifier(verifierAlgorithmIdentifier, xdhSigAlg.c509AlgorithmIdentifier(),
        HashAlgo.SHA512);
  }

  @Override
  public ContentVerifier getForC509(int verifierAlgorithmIdentifier) throws GenerationException {
    HashAlgo hash = null;
    if (xdhSigAlg != null) {
      if (xdhSigAlg.c509AlgorithmIdentifier() != null
          && xdhSigAlg.c509AlgorithmIdentifier() == verifierAlgorithmIdentifier) {
        hash = HashAlgo.SHA512;
      }
    } else {
      switch (verifierAlgorithmIdentifier) {
        case ConstSignatureAlgorithm.sa_ecdhPop_sha256_hmac_sha256:
          hash = HashAlgo.SHA256;
          break;
        case ConstSignatureAlgorithm.sa_ecdhPop_sha384_hmac_sha384:
          hash = HashAlgo.SHA384;
          break;
        case ConstSignatureAlgorithm.sa_ecdhPop_sha512_hmac_sha512:
          hash = HashAlgo.SHA512;
          break;
        default:
          break;
      }
    }

    if (hash == null) {
      throw new GenerationException(
          "given public key is not suitable for the algorithm "
              + ConstSignatureAlgorithm.describe(verifierAlgorithmIdentifier));
    }

    AlgorithmIdentifier x509AlgId = (xdhSigAlg == null) ? null : xdhSigAlg.algorithmIdentifier();
    return newVerifier(x509AlgId, verifierAlgorithmIdentifier, hash);
  }

  private XDHContentVerifier newVerifier(
      AlgorithmIdentifier x509AlgId, Integer c509AlgId, HashAlgo hash)
      throws GenerationException {
    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = ownerKeyAndCert.encodedSubject();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    byte[] trailingInfo = ownerKeyAndCert.encodedIssuer();
    byte[] k = hash.hash(leadingInfo, zz, trailingInfo);

    String hmacAlgorithm = "HMAC-" + hash.jceName().replace("-", "");
    Mac hmac;
    try {
      hmac = cryptoApi.newMac(hmacAlgorithm);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new GenerationException(ex.getMessage());
    }

    return new XDHContentVerifier(x509AlgId, c509AlgId, hmac,
        new SecretKeySpec(k, hmacAlgorithm), ownerKeyAndCert);
  }

}
