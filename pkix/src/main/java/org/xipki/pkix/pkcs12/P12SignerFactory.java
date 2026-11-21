// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.Base64;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.sign.SignerFactory;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.codec.util.IoUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * P12 Signer Factory.
 *
 * @author Lijun Liao (xipki)
 */
public class P12SignerFactory implements SignerFactory {

  private static final String TYPE_PKCS12 = "pkcs12";
  private static final String TYPE_JCEKS = "jceks";

  private static final Set<String> types = Set.of(TYPE_PKCS12, TYPE_JCEKS);

  private final String basedir;

  public P12SignerFactory() {
    this(null);
  }

  /**
   * Constructor.
   * @param basedir the base directory, against which a relative keystore file
   *                ({@code file:<path>}) is resolved. May be {@code null}.
   */
  public P12SignerFactory(String basedir) {
    this.basedir = basedir;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return types;
  }

  @Override
  public boolean canCreateSigner(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public ConcurrentSigner newSigner(
      SecurityFactory securityFactory, String type, SignerConf conf, X509Cert[] certificateChain)
      throws GenerationException {
    return newSigner(true, securityFactory, type, conf, certificateChain, null);
  }

  @Override
  public ConcurrentSigner newSigner(
      SecurityFactory securityFactory, String type, SignerConf conf, C509Cert[] certificateChain)
      throws GenerationException {
    return newSigner(false, securityFactory, type, conf, null, certificateChain);
  }

  private ConcurrentSigner newSigner(
      boolean x509, SecurityFactory securityFactory, String type, SignerConf conf,
      X509Cert[] x509CertChain, C509Cert[] c509CertChain)
      throws GenerationException {
    if (securityFactory == null) {
      throw new GenerationException("securityFactory could not be null");
    }

    if (!canCreateSigner(type)) {
      throw new GenerationException("unknown signer type " + type);
    }

    Integer iParallelism;
    try {
      iParallelism = conf.parallelism();
    } catch (InvalidConfException e) {
      throw new GenerationException(e);
    }

    int parallelism = Objects.requireNonNullElseGet(
        iParallelism, securityFactory::dfltSignerParallelism);

    String passwordHint = conf.password();
    char[] password = getPassword(passwordHint);

    String keystore = conf.keystore();
    String keyLabel = conf.keyLabel();

    try (InputStream keystoreStream = getInputStream(keystore)) {
      SignAlgo sigAlgo = conf.algo();
      if (sigAlgo != null && sigAlgo.isMac()) {
        P12MacContentSignerBuilder signerBuilder =
            new P12MacContentSignerBuilder(type, keystoreStream, password, keyLabel, password);
        return signerBuilder.createSigner(sigAlgo, parallelism);
      } else {
        if (x509) {
          X509KeypairWithCert keypairWithCert = X509KeypairWithCert.fromPKCS12Keystore(
              keystoreStream, password, keyLabel, password, x509CertChain);
          if (sigAlgo == null) {
            SubjectPublicKeyInfo pkInfo = keypairWithCert.certChain()[0].subjectPublicKeyInfo();
            sigAlgo = SignAlgo.getDefaultSignAlgo(KeySpec.ofPublicKey(pkInfo), conf.mode());
            conf.setAlgo(sigAlgo);
          }

          // by the algorithm OID: Key.getAlgorithm() is provider-specific (the JDK returns "XDH")
          EcCurveEnum curve = KeyInfoUtil.getCurve(keypairWithCert.getKey());
          if (curve == EcCurveEnum.X25519 || curve == EcCurveEnum.X448) {
            X509P12XdhMacSignerBuilder signerBuilder =
                getP12XdhMacContentSignerBuilder(conf, keypairWithCert);
            return signerBuilder.createSigner(parallelism);
          }

          if (SignAlgo.KEM_HMAC_SHA256 == sigAlgo) {
            // MLKEM, Composite MLKEM
            SubjectPublicKeyInfo publicKeyInfo =
                keypairWithCert.certChain()[0].subjectPublicKeyInfo();
            X509P12KemMacContentSignerBuilder signerBuilder =
                new X509P12KemMacContentSignerBuilder(keypairWithCert,
                    securityFactory.csrControl().generateKemEncapKey(publicKeyInfo));
            return signerBuilder.createSigner(sigAlgo, parallelism);
          } else {
            P12ContentSignerBuilder signerBuilder = new P12ContentSignerBuilder(keypairWithCert);
            return signerBuilder.createSigner(sigAlgo, parallelism);
          }
        } else {
          // c509
          C509KeypairWithCert keypairWithCert = C509KeypairWithCert.fromPKCS12Keystore(
              keystoreStream, password, keyLabel, password, c509CertChain);
          if (sigAlgo == null) {
            C509SubjectPublicKey pkInfo = keypairWithCert.certChain()[0].subjectPublicKeyInfo();
            sigAlgo = SignAlgo.getDefaultSignAlgo(KeySpec.ofPublicKey(pkInfo), conf.mode());
            conf.setAlgo(sigAlgo);
          }

          // by the algorithm OID: Key.getAlgorithm() is provider-specific (the JDK returns "XDH")
          EcCurveEnum curve = KeyInfoUtil.getCurve(keypairWithCert.getKey());
          if (curve == EcCurveEnum.X25519 || curve == EcCurveEnum.X448) {
            C509P12XdhMacSignerBuilder signerBuilder =
                getP12XdhMacContentSignerBuilder(conf, keypairWithCert);
            return signerBuilder.createSigner(parallelism);
          }

          if (SignAlgo.KEM_HMAC_SHA256 == sigAlgo) {
            // MLKEM, Composite MLKEM
            C509SubjectPublicKey publicKeyInfo =
                keypairWithCert.certChain()[0].subjectPublicKeyInfo();
            C509P12KemMacContentSignerBuilder signerBuilder =
                new C509P12KemMacContentSignerBuilder(keypairWithCert,
                    securityFactory.csrControl().generateKemEncapKey(publicKeyInfo));
            return signerBuilder.createSigner(sigAlgo, parallelism);
          } else {
            P12ContentSignerBuilder signerBuilder = new P12ContentSignerBuilder(keypairWithCert);
            return signerBuilder.createSigner(sigAlgo, parallelism);
          }
        }
      }
    } catch (XiSecurityException | IOException | InvalidConfException | CodecException ex) {
      throw new GenerationException(String.format(
          "%s: %s", ex.getClass().getName(), ex.getMessage()), ex);
    }
  } // method newSigner

  private static X509P12XdhMacSignerBuilder getP12XdhMacContentSignerBuilder(
      SignerConf conf, X509KeypairWithCert keypairWithCert)
      throws GenerationException, XiSecurityException {
    // peer certificate is needed
    List<X509Cert> peerCerts = conf.peerCertificates();
    if (peerCerts == null || peerCerts.isEmpty()) {
      throw new GenerationException("no peer certificate is specified");
    }

    X509Cert myCert = keypairWithCert.certChain()[0];
    X509Cert peerCert = null;

    AlgorithmIdentifier myKeyAlg = myCert.subjectPublicKeyInfo().getAlgorithm();
    for (X509Cert m : peerCerts) {
      if (m.subjectPublicKeyInfo().getAlgorithm().equals(myKeyAlg)) {
        peerCert = m;
        break;
      }
    }

    if (peerCert == null) {
      throw new GenerationException("could not find peer certificate");
    }

    return new X509P12XdhMacSignerBuilder(keypairWithCert, peerCert);
  }

  private static C509P12XdhMacSignerBuilder getP12XdhMacContentSignerBuilder(
      SignerConf conf, C509KeypairWithCert keypairWithCert)
      throws GenerationException, XiSecurityException {
    // peer certificate is needed
    List<C509Cert> peerCerts = conf.peerC509Certificates();
    if (peerCerts == null || peerCerts.isEmpty()) {
      throw new GenerationException("no peer certificate is specified");
    }

    C509Cert myCert = keypairWithCert.certChain()[0];
    C509Cert peerCert = null;

    int myKeyAlg = myCert.subjectPublicKeyInfo().algorithm();
    for (C509Cert m : peerCerts) {
      if (m.subjectPublicKeyInfo().algorithm() == myKeyAlg) {
        peerCert = m;
        break;
      }
    }

    if (peerCert == null) {
      throw new GenerationException("could not find peer certificate");
    }

    return new C509P12XdhMacSignerBuilder(keypairWithCert, peerCert);
  }

  private char[] getPassword(String passwordHint) throws GenerationException {
    char[] password;
    if (passwordHint == null) {
      password = null;
    } else if (!passwordHint.contains(":")) {
      password = passwordHint.toCharArray();
    } else {
      try {
        password = Passwords.resolvePassword(passwordHint);
      } catch (PasswordResolverException ex) {
        throw new GenerationException("could not resolve password: " + ex.getMessage());
      }
    }
    return password;
  }

  private InputStream getInputStream(String str) throws GenerationException {
    if (StringUtil.startsWithIgnoreCase(str, "base64:")) {
      return new ByteArrayInputStream(Base64.decode(str.substring(7))); // "base64:".length() = 7
    } else if (StringUtil.startsWithIgnoreCase(str, "file:")) {
      String fn = str.substring(5); // "file:".length() = 5
      try {
        return Files.newInputStream(Paths.get(IoUtil.resolvePath(basedir, fn)));
      } catch (IOException ex) {
        throw new GenerationException("file not found: " + fn);
      }
    } else {
      throw new GenerationException("unknown content format");
    }
  } // method getInputStream
}
