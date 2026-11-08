// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.util.exception.NoIdleSignerException;
import org.xipki.util.misc.CollectionUtil;
import org.xipki.util.misc.LogUtil;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dflt Concurrent Signer definition.
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

  private X509Cert[] certificateChain;

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
    this.algorithm = SignAlgo.ofAlgorithmIdentifier(
        signers.get(0).x509Signer().getAlgorithmIdentifier());
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
  public void setX509CertChain(X509Cert[] certificateChain) {
    if (CollectionUtil.isEmpty(certificateChain)) {
      this.certificateChain = null;
      return;
    }

    this.certificateChain = certificateChain;
    setPublicKey(certificateChain[0].publicKey());
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
    return CollectionUtil.isEmpty(certificateChain) ? null : certificateChain[0];
  }

  @Override
  public X509Cert[] x509CertChain() {
    return certificateChain;
  }

  @Override
  public boolean isHealthy() {
    Signer signer = null;
    try {
      signer = borrowSigner();
      ContentSigner x509Signer = signer.x509Signer();
      byte[] signature = x509Signer.atomicSign(new byte[]{1, 2, 3, 4});
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
  public byte[] x509Sign(byte[] data) throws NoIdleSignerException, SignatureException {
    Signer signer = borrowSigner();
    try {
      ContentSigner x509Signer = signer.x509Signer();
      return x509Signer.atomicSign(data);
    } finally {
      requiteSigner(signer);
    }
  } // method sign

  @Override
  public byte[][] x509Sign(byte[][] data) throws NoIdleSignerException, SignatureException {
    byte[][] signatures = new byte[data.length][];
    Signer signer = borrowSigner();

    try {
      ContentSigner x509Signer = signer.x509Signer();
      for (int i = 0; i < data.length; i++) {
        signatures[i] = x509Signer.atomicSign(data[i]);
      }
    } finally {
      requiteSigner(signer);
    }

    return signatures;
  } // method sign

}
