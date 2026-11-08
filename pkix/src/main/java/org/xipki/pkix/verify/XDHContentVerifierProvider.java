// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.asn1.crmf.DhSigStatic;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
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

    private class HmacOutputStream extends OutputStream {

      @Override
      public void write(int bb) throws IOException {
        hmac.update((byte) bb);
      }

      @Override
      public void write(byte[] bytes) throws IOException {
        hmac.update(bytes, 0, bytes.length);
      }

      @Override
      public void write(byte[] bytes, int off, int len) throws IOException {
        hmac.update(bytes, off, len);
      }

    } // class HmacOutputStream

    private final AlgorithmIdentifier algId;

    private final HmacOutputStream outputStream;

    private final Mac hmac;

    private final SecretKey macKey;

    private XDHContentVerifier(AlgorithmIdentifier algId, Mac hmac, SecretKey macKey) {
      this.algId = algId;
      this.hmac = hmac;
      this.macKey = macKey;
      this.outputStream = new HmacOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      try {
        hmac.init(macKey);
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
      return MessageDigest.isEqual(expectedHashValue, hmac.doFinal());
    }

  } // class XDHContentVerifier

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final SecretKey hmacKey;

  private final String hmacAlgorithm;

  private final Asn1Oid sigAlgOid;

  public XDHContentVerifierProvider(PublicKey verifyKey, DHSigStaticKeyCertPair ownerKeyAndCert)
      throws InvalidKeyException {
    Args.notNull(ownerKeyAndCert, "ownerKeyAndCert");

    Args.notNull(verifyKey, "verifyKey");
    // by the algorithm OID: PublicKey.getAlgorithm() is provider-specific (e.g. the JDK returns
    // "XDH" for X25519 and X448)
    EcCurveEnum curveEnum = KeyInfoUtil.getCurve(verifyKey);
    String keyAlgName = (curveEnum == null) ? verifyKey.getAlgorithm() : curveEnum.name();

    HashAlgo hash;
    if (EcCurveEnum.X25519 == curveEnum) {
      this.sigAlgOid = XipkiOIDs.id_alg_dhPop_x25519;
      this.hmacAlgorithm = "HMAC-SHA512";
      hash = HashAlgo.SHA512;
    } else if (EcCurveEnum.X448 == curveEnum) {
      this.sigAlgOid = XipkiOIDs.id_alg_dhPop_x448;
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
    if (!this.sigAlgOid.equals(oid)) {
      throw new GenerationException(
          "given public key is not suitable for the algorithm " + oid.getId());
    }

    Mac hmac;
    try {
      hmac = cryptoApi.newMac(hmacAlgorithm);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new GenerationException(ex.getMessage());
    }

    return new XDHContentVerifier(verifierAlgorithmIdentifier, hmac, hmacKey);
  }

}
