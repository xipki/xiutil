// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.asn1.cms.IssuerAndSerialNumber;
import org.xipki.asn1.crmf.DhSigStatic;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.XiArrays;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.DfltConcurrentSigner;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.crypto.core.EcCurveEnum;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * P12 Xdh Mac Signer Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class P12XdhMacSignerBuilder {

  private static class XdhMacContentSigner extends HmacSigner {

    private final byte[] prefix;

    private final int hashLen;

    private final ContentSigner contentSigner;

    // TODO: consider C509IssuerAndSerialNumber
    private XdhMacContentSigner(SignAlgo signAlgo, SecretKey signingKey,
                                IssuerAndSerialNumber peerIssuerAndSerial)
        throws XiSecurityException {
      super(signAlgo, signingKey);
      this.hashLen = signAlgo.hashAlgo().length();

      byte[] encodedSig = new DhSigStatic(peerIssuerAndSerial, new byte[hashLen]).getEncoded();
      this.prefix = Arrays.copyOfRange(encodedSig, 0, encodedSig.length - hashLen);

      final ContentSigner superX509Signer = super.contentSigner();

      this.contentSigner = new ContentSigner() {
        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
          return superX509Signer.getAlgorithmIdentifier();
        }

        @Override
        public Integer getC509AlgorithmIdentifier() {
          return superX509Signer.getC509AlgorithmIdentifier();
        }

        @Override
        public OutputStream getOutputStream() {
          return superX509Signer.getOutputStream();
        }

        /**
         * Signature has the following format.
         * <pre>
         * DhSigStatic ::= SEQUENCE {
         *   issuerAndSerial IssuerAndSerialNumber OPTIONAL,
         *   hashValue       MessageDigest
         * }
         *
         * MessageDigest ::= OCTET STRING
         * </pre>
         */
        @Override
        public byte[] getSignature() throws SignatureException {
          byte[] hashValue = superX509Signer.getSignature();
          return buildDhSig(hashValue);
        }

        @Override
        public byte[] atomicSign(byte[] toBeSignData) throws SignatureException {
          byte[] hashValue = superX509Signer.atomicSign(toBeSignData);
          return buildDhSig(hashValue);
        }

        private byte[] buildDhSig(byte[] hashValue) throws SignatureException {
          if (hashValue.length != hashLen) {
            throw new SignatureException(
                "exception obtaining signature: invalid signature length");
          }
          return XiArrays.concatenate(prefix, hashValue);
        }
      };
    }

    @Override
    public ContentSigner contentSigner() {
      return this.contentSigner;
    }

  } // class XdhMacContentSigner

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private SecretKey key;

  private SignAlgo algo;

  private IssuerAndSerialNumber peerIssuerAndSerial;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public P12XdhMacSignerBuilder(
      X509Cert peerCert, PrivateKey privateKey, PublicKey publicKey) throws XiSecurityException {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = null;
    init(Args.notNull(privateKey, "privateKey"), Args.notNull(peerCert, "peerCert"));
  }

  public P12XdhMacSignerBuilder(KeypairWithCert keypairWithCert, X509Cert peerCert)
      throws XiSecurityException {
    this.publicKey = Args.notNull(keypairWithCert, "keypairWithCert").publicKey();

    this.certificateChain = keypairWithCert.x509CertChain();
    init(keypairWithCert.getKey(), Args.notNull(peerCert, "peerCert"));
  }

  /**
   * Constructor with the shared secret computed elsewhere, e.g. in a PKCS#11 token.
   * @param curve X25519 or X448.
   * @param zz the shared secret of the own private key and the public key of peerCert.
   * @param peerCert the certificate of the static DH key of the peer (CA).
   * @param publicKey the own public key.
   * @param certificateChain the own certificate chain, may be null.
   * @throws XiSecurityException if curve is not X25519 or X448, or does not match peerCert.
   */
  public P12XdhMacSignerBuilder(
      EcCurveEnum curve, byte[] zz, X509Cert peerCert, PublicKey publicKey,
      X509Cert[] certificateChain) throws XiSecurityException {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = certificateChain;
    Args.notNull(peerCert, "peerCert");
    initAlgo(curve, peerCert);
    initKey(Args.notNull(zz, "zz"), peerCert);
  }

  private void init(PrivateKey privateKey, X509Cert peerCert) throws XiSecurityException {
    // by the algorithm OID: Key.getAlgorithm() is provider-specific (the JDK returns "XDH")
    EcCurveEnum curve = KeyInfoUtil.getCurve(privateKey);
    initAlgo(curve, peerCert);

    // compute the shared secret
    byte[] zz;
    try {
      KeyAgreement keyAgreement = cryptoApi.newKeyAgreement(curve.name());
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(peerCert.publicKey(), true);
      zz = keyAgreement.generateSecret();
    } catch (GeneralSecurityException | RuntimeException ex) {
      throw new XiSecurityException("KeyChange error", ex);
    }

    initKey(zz, peerCert);
  } // method init

  private void initAlgo(EcCurveEnum curve, X509Cert peerCert) {
    if (EcCurveEnum.X25519 == curve) {
      this.algo = SignAlgo.DHPOP_X25519;
    } else if (EcCurveEnum.X448 == curve) {
      this.algo = SignAlgo.DHPOP_X448;
    } else {
      throw new IllegalArgumentException("unsupported key, curve: " + curve);
    }

    if (curve != KeyInfoUtil.getCurve(peerCert.publicKey())) {
      throw new IllegalArgumentException("peerCert and key does not match");
    }
  }

  /**
   * Derives the MAC key from the shared secret zz, as defined in RFC 6955.
   */
  private void initKey(byte[] zz, X509Cert peerCert) {
    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = peerCert.subject().getEncoded();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    byte[] trailingInfo = peerCert.issuer().getEncoded();

    byte[] k = this.algo.hashAlgo().hash(leadingInfo, zz, trailingInfo);
    this.key = new SecretKeySpec(k, algo.jceName());
    this.peerIssuerAndSerial = new IssuerAndSerialNumber(
        peerCert.issuer(), peerCert.serialNumber());
  }

  public ConcurrentSigner createSigner(int parallelism) throws XiSecurityException {
    List<Signer> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      signers.add(new XdhMacContentSigner(algo, key, peerIssuerAndSerial));
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(HashAlgo.SHA1.hash(key.getEncoded()));

    if (certificateChain != null) {
      concurrentSigner.setX509CertChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
