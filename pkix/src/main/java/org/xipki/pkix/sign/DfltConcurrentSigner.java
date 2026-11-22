// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.sign.C509ExtendedSigner;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.exception.NoIdleSignerException;
import org.xipki.util.misc.CollectionUtil;
import org.xipki.util.misc.LogUtil;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Default Concurrent Signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class DfltConcurrentSigner implements ConcurrentSigner {

  private static final Logger LOG = LoggerFactory.getLogger(DfltConcurrentSigner.class);

  private static final AtomicInteger NAME_INDEX = new AtomicInteger(1);

  private static int defaultSignServiceTimeout = 10000; // 10 seconds

  private final ArrayBlockingQueue<Signer> signers;

  private final String name;

  private final SignAlgo algorithm;

  private final boolean mac;

  private byte[] sha1OfMacKey;

  private final Key signingKey;

  private PublicKey publicKey;

  private X509Cert[] x509CertChain;

  private C509Cert[] c509CertChain;

  private CoseC509 coseC509CertChain;

  private final MyC509Signer c509Signer = new MyC509Signer();

  private final Map<Integer, byte[]> ocspSignerIdMap = new HashMap<>();

  private class MyC509Signer implements C509ExtendedSigner {

    @Override
    public byte[] certHash(int c509HashAlg) {
      byte[] signerId = ocspSignerIdMap.get(c509HashAlg);
      if (signerId == null) {
        throw new IllegalArgumentException("could not get C509 SignerId for "
            + ConstHashAlgorithm.describe(c509HashAlg));
      }
      return signerId;
    }

    @Override
    public int c509Algorithm() {
      return algorithm.c509AlgorithmIdentifier();
    }

    @Override
    public SignatureValue c509Sign(byte[] tbs) throws SignatureException {
      return atomicC509Sign(tbs);
    }

    @Override
    public CoseC509 certificates() {
      return coseC509CertChain;
    }

    @Override
    public boolean isHealthy() {
      return DfltConcurrentSigner.this.isHealthy();
    }

  }

  static {
    final String propKey = "org.xipki.security.signservice.timeout";
    String str = System.getProperty(propKey);

    if (str != null) {
      int vi = Integer.parseInt(str);
      // valid value is between 0 and 60 seconds
      if (vi < 0 || vi > 60 * 1000) {
        LOG.error("invalid {}: {}", propKey, vi);
      } else {
        LOG.info("use {}: {}", propKey, vi);
        defaultSignServiceTimeout = vi;
      }
    }
  } // method static

  public DfltConcurrentSigner(boolean mac, List<Signer> signers) throws NoSuchAlgorithmException {
    this(mac, signers, null);
  }

  public DfltConcurrentSigner(boolean mac, List<Signer> signers, Key signingKey)
      throws NoSuchAlgorithmException {
    Args.notEmpty(signers, "signers");

    this.mac = mac;

    ContentSigner csigner = signers.get(0).contentSigner();
    SignAlgo signAlgo = null;
    try {
      signAlgo = SignAlgo.ofAlgorithmIdentifier(csigner.x509Algorithm());
    } catch (Exception e) {
      signAlgo = SignAlgo.ofC509AlgorithmIdentifier(csigner.c509Algorithm());
    }
    this.algorithm = signAlgo;

    this.signers = new ArrayBlockingQueue<>(signers.size());
    this.signers.addAll(signers);

    this.signingKey = signingKey;
    this.name = "defaultSigner-" + NAME_INDEX.getAndIncrement();
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public boolean isMac() {
    return mac;
  }

  public void setSha1DigestOfMacKey(byte[] digest) {
    if (digest == null) {
      this.sha1OfMacKey = null;
    } else if (digest.length == 20) {
      this.sha1OfMacKey = Arrays.copyOf(digest, 20);
    } else {
      throw new IllegalArgumentException("invalid sha1Digest.length (" + digest.length + " != 20)");
    }
  }

  @Override
  public byte[] sha1OfMacKey() {
    return (sha1OfMacKey == null) ? null : Arrays.copyOf(sha1OfMacKey, 20);
  }

  @Override
  public SignAlgo algorithm() {
    return algorithm;
  }

  @Override
  public Signer borrowSigner() throws NoIdleSignerException {
    return borrowSigner(defaultSignServiceTimeout);
  }

  /**
   * Borrows a signer.
   *
   * @param soTimeout timeout in milliseconds, 0 for infinitely.
   */
  @Override
  public Signer borrowSigner(int soTimeout) throws NoIdleSignerException {
    Signer signer = null;
    try {
      signer = signers.poll(soTimeout, TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
    }

    return Optional.ofNullable(signer).orElseThrow(
        () -> new NoIdleSignerException("no idle signer available"));
  }

  @Override
  public void requiteSigner(Signer signer) {
    signers.add(signer);
  }

  @Override
  public void initialize(String conf) throws XiSecurityException {
  }

  @Override
  public Key signingKey() {
    return signingKey;
  }

  @Override
  public void setX509CertChain(X509Cert[] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      this.x509CertChain = null;
      return;
    }

    this.x509CertChain = certchain;
    if (publicKey == null) {
      setPublicKey(certchain[0].publicKey());
    }
  }

  @Override
  public PublicKey publicKey() {
    return publicKey;
  }

  @Override
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public X509Cert x509Cert() {
    return CollectionUtil.isEmpty(x509CertChain) ? null : x509CertChain[0];
  }

  @Override
  public X509Cert[] x509CertChain() {
    return x509CertChain;
  }

  @Override
  public C509Cert c509Cert() {
    return CollectionUtil.isEmpty(c509CertChain) ? null : c509CertChain[0];
  }

  @Override
  public void setC509CertChain(C509Cert[] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      this.c509CertChain = null;
      this.coseC509CertChain = null;
      this.ocspSignerIdMap.clear();
      return;
    }

    this.c509CertChain = certchain;
    if (publicKey == null) {
      setPublicKey(certchain[0].publicKey());
    }

    List<C509Certificate> rawCerts = new ArrayList<>(certchain.length);
    for (C509Cert cert : certchain) {
      rawCerts.add(cert.getCert());
    }
    this.coseC509CertChain = new CoseC509(rawCerts);
    byte[] encodedCert = rawCerts.get(0).getEncoded();
    for (HashAlgo ha : HashAlgo.values()) {
      Integer c509AlgId = ha.c509AlgId();
      if (c509AlgId != null) {
        ocspSignerIdMap.put(c509AlgId, ha.hash(encodedCert));
      }
    }
  }

  @Override
  public C509Cert[] c509CertChain() {
    return c509CertChain;
  }

  @Override
  public boolean isHealthy() {
    Signer signer = null;
    try {
      signer = borrowSigner();
      ContentSigner x509Signer = signer.contentSigner();
      byte[] signature = x509Signer.atomicX509Sign(new byte[]{1, 2, 3, 4});
      return signature != null && signature.length > 0;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return false;
    } finally {
      if (signer != null) {
        requiteSigner(signer);
      }
    }
  }

  @Override
  public void close() {
  }

  @Override
  public AlgorithmIdentifier x509Algorithm() {
    return algorithm.algorithmIdentifier();
  }

  @Override
  public byte[] atomicX509Sign(byte[] data) throws SignatureException {
    Signer signer;
    try {
      signer = borrowSigner();
    } catch (NoIdleSignerException e) {
      throw new SignatureException(e);
    }

    try {
      ContentSigner contentSigner = signer.contentSigner();
      return contentSigner.atomicX509Sign(data);
    } finally {
      requiteSigner(signer);
    }
  } // method sign

  @Override
  public int c509Algorithm() {
    return algorithm.c509AlgorithmIdentifier();
  }

  @Override
  public SignatureValue atomicC509Sign(byte[] data) throws SignatureException {
    Signer signer;
    try {
      signer = borrowSigner();
    } catch (NoIdleSignerException e) {
      throw new SignatureException(e);
    }

    try {
      ContentSigner contentSigner = signer.contentSigner();
      return contentSigner.atomicC509Sign(data);
    } finally {
      requiteSigner(signer);
    }
  }

  @Override
  public C509ExtendedSigner asC509Signer() {
    return c509Signer;
  }

}
