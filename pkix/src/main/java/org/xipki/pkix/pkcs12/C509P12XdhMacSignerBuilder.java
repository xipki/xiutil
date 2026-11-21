// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.c509.C509DhSigStaticSignatureValue;
import org.xipki.c509.name.C509IssuerAndSerialNumber;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.DfltConcurrentSigner;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.pkix.sign.Signer;

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
import java.util.List;

/**
 * P12 Xdh Mac Signer Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class C509P12XdhMacSignerBuilder {

  private static class C509XdhMacContentSigner extends HmacSigner {

    private final ContentSigner contentSigner;

    private C509XdhMacContentSigner(SignAlgo signAlgo, SecretKey signingKey,
                                    C509IssuerAndSerialNumber peerIssuerAndSerial)
        throws XiSecurityException {
      super(signAlgo, signingKey);
      Args.notNull(peerIssuerAndSerial, "peerIssuerAndSerial");

      final ContentSigner superContentSigner = super.contentSigner();
      final CborEncodedItem encodedPeerIssuer;
      try {
        encodedPeerIssuer = CborEncodedItem.getInstance(peerIssuerAndSerial.issuer().getEncoded());
      } catch (CodecException e) {
        throw new XiSecurityException(e);
      }

      this.contentSigner = new ContentSigner() {
        @Override
        public AlgorithmIdentifier x509Algorithm() {
          throw new IllegalStateException("This XDH signer is not X509-capable");
        }

        @Override
        public int c509Algorithm() {
          return superContentSigner.c509Algorithm();
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
          throw new IllegalStateException("This XDH signer is not C509-capable");
        }

        @Override
        public byte[] atomicX509Sign(byte[] toBeSignData) throws SignatureException {
          throw new IllegalStateException("This XDH signer is not C509-capable");
        }

        @Override
        public SignatureValue getC509Signature() throws SignatureException {
          byte[] hashValue = superContentSigner.getX509Signature();
          return buildDhSig(hashValue);
        }

        /**
         * Atomic operation to compute signature over the given data.
         * @param dataToSign the data to be signed.
         * @return the signature
         * @throws SignatureException when error occurred.
         */
        @Override
        public SignatureValue atomicC509Sign(byte[] dataToSign) throws SignatureException {
          byte[] hashValue = superContentSigner.atomicX509Sign(dataToSign);
          return buildDhSig(hashValue);
        }

        private C509DhSigStaticSignatureValue buildDhSig(byte[] hashValue)
            throws SignatureException {
          if (hashValue.length != signAlgo.hashAlgo().length()) {
            throw new SignatureException(
                "exception obtaining signature: invalid signature length");
          }

          try {
            return new C509DhSigStaticSignatureValue(hashValue, encodedPeerIssuer,
                peerIssuerAndSerial.serialNumber());
          } catch (CodecException ex) {
            throw new SignatureException("error building DhSigStatic: " + ex.getMessage(), ex);
          }
        }
      };
    }

    @Override
    public ContentSigner contentSigner() {
      return this.contentSigner;
    }

  } // class C509XdhMacContentSigner

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private SecretKey key;

  private SignAlgo algo;

  private final PublicKey publicKey;

  private C509IssuerAndSerialNumber peerIssuerAndSerial;

  private final C509Cert[] certChain;

  public C509P12XdhMacSignerBuilder(
      C509Cert peerCert, PrivateKey privateKey, PublicKey publicKey) throws XiSecurityException {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certChain = null;
    init(Args.notNull(privateKey, "privateKey"), Args.notNull(peerCert, "peerCert"));
  }

  public C509P12XdhMacSignerBuilder(C509KeypairWithCert keypairWithCert, C509Cert peerCert)
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
   */
  public C509P12XdhMacSignerBuilder(
      EcCurveEnum curve, byte[] zz, C509Cert peerCert, PublicKey publicKey,
      C509Cert[] x509CertChain) {
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certChain = x509CertChain;
    Args.notNull(peerCert, "peerCert");
    initAlgo(curve, peerCert);
    initKey(Args.notNull(zz, "zz"), peerCert);
  }

  private void init(PrivateKey privateKey, C509Cert peerCert) throws XiSecurityException {
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

  private void initAlgo(EcCurveEnum curve, C509Cert peerCert) {
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
  private void initKey(byte[] zz, C509Cert peerCert) {
    // as defined in RFC 6955, raw hash algorithm is used as KDF

    // LeadingInfo := Subject Distinguished Name from certificate
    byte[] leadingInfo = peerCert.subject().getEncoded();
    // TrailingInfo ::= Issuer Distinguished Name from certificate
    C509Name issuer = peerCert.issuer();
    byte[] trailingInfo = issuer == null ? new byte[]{(byte) 0xF6} : issuer.getEncoded();

    byte[] k = this.algo.hashAlgo().hash(leadingInfo, zz, trailingInfo);
    this.key = new SecretKeySpec(k, algo.jceName());
    this.peerIssuerAndSerial = new C509IssuerAndSerialNumber(
        peerCert.issuer(), peerCert.serialNumber());
  }

  public ConcurrentSigner createSigner(int parallelism) throws XiSecurityException {
    List<Signer> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));

    for (int i = 0; i < parallelism; i++) {
      signers.add(new C509XdhMacContentSigner(algo, key, peerIssuerAndSerial));
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
      concurrentSigner.setC509CertChain(certChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }

    return concurrentSigner;
  } // method createSigner

}
