// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.id.XipkiOIDs;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;

import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * Kem Hmac Signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class KemHmacSigner implements Signer {

  private final static AlgorithmIdentifier ALG_ID =
      new AlgorithmIdentifier(XipkiOIDs.id_alg_KEM_HMAC_SHA256);
  private final static int C509_ALG_ID = ConstSignatureAlgorithm.SIG_KEM_HMAC_SHA256;

  private static final byte[] ENCODED_ALG_ID = ALG_ID.getEncoded();

  private final String id;
  private final HmacSigner macSigner;

  public KemHmacSigner(String id, SecretKey macKey) throws XiSecurityException {
    this.id = Args.notNull(id, "id");
    Args.notNull(macKey, "macKey");
    this.macSigner = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
  }

  @Override
  public ContentSigner contentSigner() {
    return new ContentSigner() {
      @Override
      public AlgorithmIdentifier x509Algorithm() {
        return ALG_ID;
      }

      @Override
      public OutputStream getOutputStream() {
        return macSigner.contentSigner().getOutputStream();
      }

      @Override
      public byte[] getX509Signature() throws SignatureException {
        byte[] rawSignature = macSigner.contentSigner().getX509Signature();
        return new KemHmacSignature(id, rawSignature).getEncoded();
      }

      @Override
      public byte[] atomicX509Sign(byte[] toBeSignData) throws SignatureException {
        byte[] rawSignature = macSigner.contentSigner().atomicX509Sign(toBeSignData);
        return new KemHmacSignature(id, rawSignature).getEncoded();
      }

      @Override
      public int c509Algorithm() {
        return C509_ALG_ID;
      }

    };
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return ENCODED_ALG_ID.clone();
  }
}
