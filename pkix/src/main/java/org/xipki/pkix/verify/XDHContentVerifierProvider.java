// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.asn1.crmf.DhSigStatic;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.c509.ConstSignatureAlgorithm;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
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
import java.security.PublicKey;
import java.time.Instant;

/**
 * XDHContent Verifier Provider.
 * (XiPKI own algorithm, based on RFC 6955).
 *
 * @author Lijun Liao (xipki)
 */
public class XDHContentVerifierProvider implements ContentVerifierProvider {

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

    private XDHContentVerifier(AlgorithmIdentifier algId, Integer c509AlgId,
                               Mac mac, SecretKey macKey) {
      this.algId = algId;
      this.c509AlgId = c509AlgId;
      this.mac = mac;
      this.macKey = macKey;
      this.outputStream = new MacOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
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
    public boolean verify(byte[] expected) {
      byte[] expectedHashValue;
      try {
        expectedHashValue = DhSigStatic.fromEncoded(expected).hashValue();
      } catch (CodecException e) {
        return false;
      }
      return MessageDigest.isEqual(expectedHashValue, mac.doFinal());
    }

    @Override
    public Integer getC509AlgorithmIdentifier() {
      return c509AlgId;
    }

  } // class XDHContentVerifier

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final SecretKey hmacKey;

  private final String hmacAlgorithm;

  private final SignAlgo sigAlg;

  public XDHContentVerifierProvider(PublicKey verifyKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    Args.notNull(ownerKeyAndCert, "ownerKeyAndCert");

    Args.notNull(verifyKey, "verifyKey");
    // by the algorithm OID: PublicKey.getAlgorithm() is provider-specific
    // (e.g. the JDK returns "XDH" for X25519 and X448)
    EcCurveEnum curveEnum = KeyInfoUtil.getCurve(verifyKey);
    String keyAlgName = (curveEnum == null) ? verifyKey.getAlgorithm() : curveEnum.name();

    HashAlgo hash;
    if (EcCurveEnum.X25519 == curveEnum) {
      this.sigAlg = SignAlgo.DHPOP_X25519;
      this.hmacAlgorithm = "HMAC-SHA512";
      hash = HashAlgo.SHA512;
    } else if (EcCurveEnum.X448 == curveEnum) {
      this.sigAlg = SignAlgo.DHPOP_X25519;
      this.hmacAlgorithm = "HMAC-SHA512";
      hash = HashAlgo.SHA512;
    }  else {
      throw new InvalidKeyException("unsupported verifyKey.getAlgorithm(): " + keyAlgName);
    }

    if (curveEnum != KeyInfoUtil.getCurve(ownerKeyAndCert.privateKey())) {
      throw new InvalidKeyException("verifyKey and ownerKeyAndCert does not match");
    }

    // compute the secret key
    byte[] zz;
    try {
      KeyAgreement keyAgreement = cryptoApi.newKeyAgreement(keyAlgName);
      keyAgreement.init(ownerKeyAndCert.privateKey());
      keyAgreement.doPhase(verifyKey, true);
      zz = keyAgreement.generateSecret();
    } catch (GeneralSecurityException | RuntimeException ex) {
      throw new InvalidKeyException("KeyChange error", ex);
    }

    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = ownerKeyAndCert.encodedSubject();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    byte[] trailingInfo = ownerKeyAndCert.encodedIssuer();
    byte[] k = hash.hash(leadingInfo, zz, trailingInfo);
    this.hmacKey = new SecretKeySpec(k, hmacAlgorithm);
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
    boolean matchOid = this.sigAlg.algorithmIdentifier() != null
        && this.sigAlg.algorithmIdentifier().getAlgorithm().equals(oid);

    if (!matchOid) {
      throw new GenerationException(
          "given public key is not suitable for the algorithm " + oid.getId());
    }

    Integer c509AlgId = null;
    try {
      SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(verifierAlgorithmIdentifier);
      c509AlgId = signAlgo.c509AlgorithmIdentifier();
    } catch (NoSuchAlgorithmException e) {
    }

    return newVerifier(verifierAlgorithmIdentifier, c509AlgId);
  }

  @Override
  public ContentVerifier getForC509(int verifierAlgorithmIdentifier) throws GenerationException {
    boolean matchOid = false;
    if (sigAlg.c509AlgorithmIdentifier() != null) {
      matchOid = sigAlg.c509AlgorithmIdentifier() == verifierAlgorithmIdentifier;
    }

    if (!matchOid) {
      throw new GenerationException(
          "given public key is not suitable for the algorithm "
              + ConstSignatureAlgorithm.getDesc(verifierAlgorithmIdentifier));
    }

    AlgorithmIdentifier x509AlgId = null;
    try {
      SignAlgo signAlgo = SignAlgo.ofC509AlgorithmIdentifier(verifierAlgorithmIdentifier);
      x509AlgId = signAlgo.algorithmIdentifier();
    } catch (NoSuchAlgorithmException e) {
    }

    return newVerifier(x509AlgId, verifierAlgorithmIdentifier);
  }

  private XDHContentVerifier newVerifier(AlgorithmIdentifier x509AlgId, Integer c509AlgId)
      throws GenerationException {
    Mac hmac;
    try {
      hmac = cryptoApi.newMac(hmacAlgorithm);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new GenerationException(ex.getMessage());
    }

    return new XDHContentVerifier(x509AlgId, c509AlgId, hmac, hmacKey);
  }

}
