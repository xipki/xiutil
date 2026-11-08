// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.DigestOutputStream;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.sign.Signer;

import java.io.OutputStream;
import java.security.SignatureException;

/**
 * P12 Composite MLDSASigner signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class P12CompositeMLDSASigner implements Signer {

  private final SignAlgo signAlgo;

  private final CompositeSigSuite algoSuite;

  private final byte[] encodedX509AlgId;

  private final DigestOutputStream os;

  private final Signer pqcSigner;

  private final Signer tradSigner;

  private final MyContentSigner contentSigner;

  private final byte[] context;

  public P12CompositeMLDSASigner(SignAlgo signAlgo, Signer pqcSigner, Signer tradSigner) {
    this.context = new byte[0]; // current no context is supported.
    this.pqcSigner = Args.notNull(pqcSigner, "pqcSigner");
    this.tradSigner = Args.notNull(tradSigner, "tradSigner");

    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    if (!signAlgo.isCompositeMLDSA()) {
      throw new IllegalArgumentException(signAlgo + " is not composite MLDSA");
    }

    this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
    this.algoSuite = signAlgo.compositeSigAlgoSuite();
    this.contentSigner = new MyContentSigner();
    this.os = new DigestOutputStream(algoSuite.ph().createDigest());
  }

  @Override
  public ContentSigner contentSigner() {
    return contentSigner;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return encodedX509AlgId.clone();
  }

  private class MyContentSigner implements ContentSigner {

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return signAlgo.algorithmIdentifier();
    }

    @Override
    public Integer getC509AlgorithmIdentifier() {
      return signAlgo.c509AlgorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public byte[] getSignature() throws SignatureException {
      byte[] digestValue = os.digest();
      byte[] m_ = CompositeSigUtil.buildM_(algoSuite, context, digestValue);

      byte[]  pqcSig =  pqcSigner.contentSigner().atomicSign(m_);
      byte[] tradSig = tradSigner.contentSigner().atomicSign(m_);
      return XiArrays.concatenate(pqcSig, tradSig);
    }
  }

}
