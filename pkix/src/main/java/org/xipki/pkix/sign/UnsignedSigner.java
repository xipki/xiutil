// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.id.AlgorithmOIDs;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.NopOutputStream;

import java.io.OutputStream;
import java.security.SignatureException;

/**
 * Unsigned Signer signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class UnsignedSigner implements Signer {

  public static final UnsignedSigner INSTANCE = new UnsignedSigner();

  private static final AlgorithmIdentifier x509AlgId =
      new AlgorithmIdentifier(AlgorithmOIDs.id_alg_unsigned);

  private static final byte[] encodedX509AlgId = Hex.decode("300a06082b06010505070624");

  private final ContentSigner x509Signer;

  private UnsignedSigner() {

    this.x509Signer = new ContentSigner() {
      @Override
      public AlgorithmIdentifier x509Algorithm() {
        return x509AlgId;
      }

      @Override
      public int c509Algorithm() {
        return ConstSignatureAlgorithm.unsigned;
      }

      @Override
      public OutputStream getOutputStream() {
        return NopOutputStream.INSTANCE;
      }

      @Override
      public byte[] getX509Signature() {
        return new byte[0];
      }

      @Override
      public byte[] atomicX509Sign(byte[] toBeSignData) throws SignatureException {
        return new byte[0];
      }

    };
  }

  @Override
  public ContentSigner contentSigner() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return encodedX509AlgId.clone();
  }

}
