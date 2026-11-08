// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Locale;

/**
 * Hmac Signer signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class HmacSigner implements Signer {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final SignAlgo algorithm;

  private final byte[] encodedX509AlgId;

  private final Mac hmac;

  private final MyContentSigner contentSigner;

  public HmacSigner(SignAlgo algorithm, SecretKey signingKey) throws XiSecurityException {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    Args.notNull(signingKey, "signingKey");
    this.encodedX509AlgId = algorithm.algorithmIdentifier().getEncoded();

    String hashJceName = algorithm.hashAlgo().jceName().toUpperCase(Locale.ROOT);
    String algName = "HMAC-" + hashJceName;
    try {
      this.hmac = cryptoApi.newMac(algName);
      byte[] keyBytes = signingKey.getEncoded();
      hmac.init(new SecretKeySpec(keyBytes, algName));
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
      throw new XiSecurityException("could not initialize HMAC", ex);
    }
    this.contentSigner = new MyContentSigner();
  }

  public SignAlgo getAlgorithm() {
    return algorithm;
  }

  @Override
  public ContentSigner contentSigner() {
    return contentSigner;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
  }

  private final class MyContentSigner implements ContentSigner {

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithm.algorithmIdentifier();
    }

    @Override
    public Integer getC509AlgorithmIdentifier() {
      return algorithm.c509AlgorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      hmac.reset();
      return new HmacOutputStream(hmac);
    }

    @Override
    public byte[] getSignature() {
      return hmac.doFinal();
    }

  }

  private static class HmacOutputStream extends OutputStream {

    private final Mac hmac;

    HmacOutputStream(Mac hmac) {
      this.hmac = hmac;
    }

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

  } // method HmacOutputStream
}
