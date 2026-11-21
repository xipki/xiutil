// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.asn1.cms.IssuerAndSerialNumber;
import org.xipki.asn1.crmf.DhSigStatic;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.XiArrays;
import org.xipki.codec.x509.AlgorithmIdentifier;
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
public class X509P12XdhMacSignerBuilder {

  private static class X509XdhMacContentSigner extends HmacSigner {

    private final byte[] prefix;

    private final int hashLen;

    private final ContentSigner contentSigner;

    private X509XdhMacContentSigner(SignAlgo signAlgo, SecretKey signingKey,
                                    IssuerAndSerialNumber peerIssuerAndSerial)
        throws XiSecurityException {
      super(signAlgo, signingKey);
      this.hashLen = signAlgo.hashAlgo().length();

      byte[] encodedSig = new DhSigStatic(peerIssuerAndSerial, new byte[hashLen]).getEncoded();
      this.prefix = Arrays.copyOfRange(encodedSig, 0, encodedSig.length - hashLen);

      final ContentSigner superContentSigner = super.contentSigner();

      this.contentSigner = new ContentSigner() {
        @Override
        public AlgorithmIdentifier x509Algorithm() {
          return superContentSigner.x509Algorithm();
        }

        @Override
        public int c509Algorithm() {
          throw new IllegalStateException("This XDH signer is not C509-capable");
        }

        @Override
        public OutputStream getOutputStream() {
          return superContentSigner.getOutputStream();
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
        public byte[] getX509Signature() throws SignatureException {
          byte[] hashValue = superContentSigner.getX509Signature();
          return buildDhSig(hashValue);
        }

        @Override
        public byte[] atomicX509Sign(byte[] toBeSignData) throws SignatureException {
          byte[] hashValue = superContentSigner.atomicX509Sign(toBeSignData);
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

  } // class X509XdhMacContentSigner

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private SecretKey key;

  private SignAlgo algo;

  private final PublicKey publicKey;

  // X.509
  private IssuerAndSerialNumber peerIssuerAndSerial;

  private final X509Cert[] certChain;

  // C.509

  public X509P12XdhMacSignerBuilder(
      X509Cert peerCert, PrivateKey privateKey, PublicKey publicKey) throws XiSecurityException {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certChain = null;
    init(Args.notNull(privateKey, "privateKey"), Args.notNull(peerCert, "peerCert"));
  }

  public X509P12XdhMacSignerBuilder(X509KeypairWithCert keypairWithCert, X509Cert peerCert)
      throws XiSecurityException {
    this.publicKey = Args.notNull(keypairWithCert, "keypairWithCert").publicKey();

    this.certChain = keypairWithCert.certChain();
    init(keypairWithCert.getKey(), Args.notNull(peerCert, "peerCert"));
  }

  /**
   * Constructor with the shared secret computed elsewhere, e.g. in a PKCS#11 token.
   * @param curve X25519 or X448.
   * @param zz the shared secret of the own private key and the public key of peerCert.
   * @param peerCert the certificate of the static DH key of the peer (CA).
   * @param publicKey the own public key.
   * @param x509CertChain the own X.509 certificate chain, may be null.
   * @throws XiSecurityException if curve is not X25519 or X448, or does not match peerCert.
   */
  public X509P12XdhMacSignerBuilder(
      EcCurveEnum curve, byte[] zz, X509Cert peerCert, PublicKey publicKey,
      X509Cert[] x509CertChain) {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certChain = x509CertChain;
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
      signers.add(new X509XdhMacContentSigner(algo, key, peerIssuerAndSerial));
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
    concurrentSigner.setSha1DigestOfMacKey(HashAlgo.SHA1.hash(key.getEncoded()));

    if (certChain != null) {
      concurrentSigner.setX509CertChain(certChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
