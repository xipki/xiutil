// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.CsrControl;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.sign.SignerFactoryRegister;
import org.xipki.pkix.sign.XDHContentVerifierFactory;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.sign.AlgorithmValidator;
import org.xipki.util.misc.LogUtil;
import org.xipki.codec.util.IoUtil;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

/**
 * Security Factory Impl.
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityFactoryImpl implements SecurityFactory {

  private static final Logger LOG = LoggerFactory.getLogger(SecurityFactoryImpl.class);

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private int defaultSignerParallelism = 32;

  private SignerFactoryRegister signerFactoryRegister;

  private String basedir;

  private CsrControl csrControl;

  static {
    // Log the System Information
    LogUtil.logSystemInfo(LOG);
  }

  public SecurityFactoryImpl() {
  }

  /**
   * Sets the base directory, against which relative files are resolved.
   * @param basedir the base directory, may be {@code null}.
   */
  public void setBasedir(String basedir) {
    this.basedir = basedir;
  }

  @Override
  public Set<String> supportedSignerTypes() {
    return signerFactoryRegister.supportedSignerTypes();
  }

  @Override
  public CsrControl csrControl() {
    if (csrControl == null) {
      // ignore if file does not exist.
      String csrConfFile = basedir == null ? "xipki/etc/csr.json"
          : IoUtil.resolvePath(basedir, "etc/csr.json");
      Path confFilePath = Path.of(csrConfFile);
      if (!Files.exists(confFilePath)) {
        confFilePath = null;
      }

      if (confFilePath != null) {
        try {
          JsonMap root = JsonParser.parseMap(confFilePath, true);
          CsrControl.CsrControlConf conf = CsrControl.CsrControlConf.parse(root);
          this.csrControl = new CsrControl(conf, basedir);
        } catch (Exception e) {
          LogUtil.error(LOG, e, "error initializing CsrControl with conf file " + csrConfFile);
        }
      }

      if (this.csrControl == null) {
        this.csrControl = new CsrControl();
      }
    }

    return csrControl;
  }

  @Override
  public ConcurrentSigner createSigner(String type, SignerConf conf, X509Cert[] certificateChain)
      throws GenerationException {
    return createSigner(true, type, conf, certificateChain, null);
  }

  @Override
  public ConcurrentSigner createSigner(String type, SignerConf conf, C509Cert[] certificateChain)
      throws GenerationException {
    return createSigner(false, type, conf, null, certificateChain);
  }

  private ConcurrentSigner createSigner(
      boolean x509, String type, SignerConf conf,
      X509Cert[] x509CertChain, C509Cert[] c509CertChain)
      throws GenerationException {
    if (csrControl() != null && conf.peerCertificates() == null) {
      conf.setPeerC509Certificates(csrControl().peerC509Certs());
    }

    ConcurrentSigner signer;
    if (x509) {
      signer = signerFactoryRegister.newSigner(this, type, conf, x509CertChain);
    } else {
      signer = signerFactoryRegister.newSigner(this, type, conf, c509CertChain);
    }

    if (signer.isMac()) {
      return signer;
    }

    SignAlgo signAlgo = signer.algorithm();
    if (signAlgo == SignAlgo.KEM_HMAC_SHA256) {
      return signer;
    }

    if (signer.publicKey() == null) {
      return signer;
    }

    validateSigner(signer, type, conf);
    return signer;
  }

  @Override
  public ContentVerifierFactory getContentVerifierFactory(
      PublicKey publicKey, DHSigStaticKeyCertPair.X509 ownerKeyAndCert, SecretKey ownerMasterKey)
      throws InvalidKeyException {
    return KeyUtil.getContentVerifierFactory(publicKey, ownerKeyAndCert, ownerMasterKey);
  }

  @Override
  public ContentVerifierFactory getContentVerifierFactory(
      PublicKey publicKey, DHSigStaticKeyCertPair.C509 ownerKeyAndCert, SecretKey ownerMasterKey)
      throws InvalidKeyException {
    return KeyUtil.getContentVerifierFactory(publicKey, ownerKeyAndCert, ownerMasterKey);
  }

  @Override
  public PublicKey generatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws InvalidKeyException {
    try {
      return KeyInfoUtil.getPublicKey(subjectPublicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  @Override
  public PublicKey generatePublicKey(C509SubjectPublicKey subjectPublicKeyInfo)
      throws InvalidKeyException {
    try {
      return KeyInfoUtil.getPublicKey(subjectPublicKeyInfo);
    } catch (InvalidKeySpecException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  @Override
  public boolean verifyPop(
      CertificationRequest csr, AlgorithmValidator algoValidator,
      DHSigStaticKeyCertPair.X509 ownerKeyAndCert, SecretKey ownerMasterKey) {
    if (algoValidator == null) {
      algoValidator = AlgorithmValidator.INSTANCE;
    }

    AlgorithmIdentifier algId = csr.getSignatureAlgorithm();

    if (!algoValidator.isAlgorithmPermitted(algId)) {
      String algoName;
      try {
        algoName = SignAlgo.ofAlgorithmIdentifier(algId).jceName();
      } catch (Exception ex) {
        algoName = algId.getAlgorithm().getId();
      }

      LOG.error("POP signature algorithm {} not permitted", algoName);
      return false;
    }

    SubjectPublicKeyInfo pkInfo = csr.getSubjectPKInfo();

    try {
      PublicKey pk = KeyInfoUtil.getPublicKey(pkInfo);
      ContentVerifierFactory cvp = getContentVerifierFactory(pk, ownerKeyAndCert, ownerMasterKey);
      return csr.isSignatureValid(cvp);
    } catch (InvalidKeyException | InvalidKeySpecException | SignatureException ex) {
      LogUtil.error(LOG, ex, "could not validate POP of CSR");
      return false;
    }
  } // method verifyPop

  @Override
  public boolean verifyPop(C509CertificationRequest csr, AlgorithmValidator algoValidator,
                           DHSigStaticKeyCertPair.C509 ownerKeyAndCert, SecretKey ownerMasterKey) {
    if (algoValidator == null) {
      algoValidator = AlgorithmValidator.INSTANCE;
    }

    int algId = csr.body().signatureAlgorithm();
    if (!algoValidator.isC509AlgorithmPermitted(algId)) {
      String algoName;
      try {
        algoName = SignAlgo.ofC509AlgorithmIdentifier(algId).jceName();
      } catch (Exception ex) {
        algoName = ConstSignatureAlgorithm.describe(algId);
      }

      LOG.error("POP signature algorithm {} not permitted", algoName);
      return false;
    }

    C509SubjectPublicKey pkInfo = csr.body().subjectPublicKey();

    try {
      PublicKey pk = KeyInfoUtil.getPublicKey(pkInfo);
      ContentVerifierFactory cvp;
      if (ConstSignatureAlgorithm.isEcdhPopSignature(algId)) {
        // sa-ecdhPop-*: the key is an EC key, which is not specific to DH PoP
        if (ownerKeyAndCert == null) {
          LOG.error("could not validate POP of CSR: ownerKeyAndCert is required but absent");
          return false;
        }
        cvp = new XDHContentVerifierFactory(pk, ownerKeyAndCert);
      } else {
        cvp = getContentVerifierFactory(pk, ownerKeyAndCert, ownerMasterKey);
      }
      return csr.verify(cvp);
    } catch (InvalidKeyException | InvalidKeySpecException | SignatureException ex) {
      LogUtil.error(LOG, ex, "could not validate POP of CSR");
      return false;
    }
  }

  @Override
  public int dfltSignerParallelism() {
    return defaultSignerParallelism;
  }

  public void setDefaultSignerParallelism(int defaultSignerParallelism) {
    this.defaultSignerParallelism = Args.positive(
        defaultSignerParallelism, "defaultSignerParallelism");
  }

  public void setSignerFactoryRegister(SignerFactoryRegister signerFactoryRegister) {
    this.signerFactoryRegister = signerFactoryRegister;
  }

  private static void validateSigner(
      ConcurrentSigner signer, String signerType, SignerConf signerConf)
      throws GenerationException {
    try {
      PublicKey publicKey = signer.publicKey();
      SignAlgo signatureAlgo = signer.algorithm();
      byte[] dummyContent = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      byte[] signatureValue = signer.atomicX509Sign(dummyContent);

      boolean valid;
      if (publicKey instanceof CompositeMLDSAPublicKey) {
        CompositeMLDSAPublicKey mKey = (CompositeMLDSAPublicKey) publicKey;
        byte[] digestValue = mKey.suite().ph().hash(dummyContent);
        valid = CompositeSigUtil.verifyHash((CompositeMLDSAPublicKey) publicKey,
                  new byte[0], digestValue, signatureValue);
      } else {
        Signature verifier = cryptoApi.newSignature(signatureAlgo.jceName());
        verifier.initVerify(publicKey);
        verifier.update(dummyContent);
        valid = verifier.verify(signatureValue);
      }

      if (!valid) {
        SignerConf copy = signerConf.copy();
        StringBuilder sb = new StringBuilder()
            .append("private key and public key does not match, key type='")
            .append(signerType).append("'; ");
        String pwd = copy.password();
        if (pwd != null) {
          copy.setPassword("****");
        }
        copy.setAlgo(signatureAlgo);
        sb.append("conf='").append(copy.conf());
        X509Cert cert = signer.x509Cert();
        if (cert != null) {
          sb.append("', certificate subject='").append(cert.subjectText()).append("'");
        }

        throw new GenerationException(sb.toString());
      }
    } catch (GeneralSecurityException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }
  } // method validateSigner

}
