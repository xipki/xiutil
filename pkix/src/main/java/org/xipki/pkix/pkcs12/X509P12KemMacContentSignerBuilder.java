// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLKEMPublicKey;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemEncapsulation;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.DfltConcurrentSigner;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.Signer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * P12 Kem Mac Content Signer Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class X509P12KemMacContentSignerBuilder {

  private final X509KeypairWithCert keypairWithCert;

  private final SecretKey macKey;

  private final String id;

  public X509P12KemMacContentSignerBuilder(X509KeypairWithCert keypairWithCert, KemEncapKey encapKey)
      throws XiSecurityException {
    this.keypairWithCert = Args.notNull(keypairWithCert, "keypairWithCert");
    Args.notNull(encapKey, "encapKey");

    // decrypt the kemCiphertext
    byte algCode = encapKey.encapulation().alg();
    byte[] macKeyValue;
    if (algCode == KemEncapsulation.ALG_KMAC_MLKEM_HMAC) {
      macKeyValue = KemUtil.mlkemDecryptSecret(
          keypairWithCert.getKey(), encapKey.encapulation());
    } else if (algCode == KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC) {
      PublicKey publicKey = keypairWithCert.publicKey();
      byte[] publicKeyData;

      if (publicKey instanceof CompositeMLKEMPublicKey) {
        publicKeyData = ((CompositeMLKEMPublicKey) publicKey).keyValue();
      } else if (publicKey != null) {
        try {
          publicKeyData = SubjectPublicKeyInfo.fromPublicKey(publicKey).subjectPublicKey();
        } catch (CodecException e) {
          throw new XiSecurityException("could not parse encoded PublicKey", e);
        }
      } else {
        publicKeyData = keypairWithCert.certChain()[0]
                          .subjectPublicKeyInfo().subjectPublicKey();
      }

      macKeyValue = KemUtil.compositeMlKemDecryptSecret(
                      keypairWithCert.getKey(), publicKeyData, encapKey.encapulation());
    } else {
      throw new XiSecurityException("unknown wrap mechanism " + algCode);
    }

    this.macKey = new SecretKeySpec(macKeyValue, "HMAC-SHA256");
    this.id = encapKey.id();
  }

  public ConcurrentSigner createSigner(SignAlgo signAlgo, int parallelism)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    if (signAlgo != SignAlgo.KEM_HMAC_SHA256) {
      throw new XiSecurityException("unknown signAlgo " + signAlgo);
    }

    List<Signer> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));
    for (int i = 0; i < parallelism; i++) {
      signers.add(new KemHmacSigner(this.id, macKey));
    }

    final boolean mac = true;
    DfltConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, keypairWithCert.getKey());
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (keypairWithCert.certChain() != null) {
      concurrentSigner.setX509CertChain(keypairWithCert.certChain());
    }

    return concurrentSigner;
  } // method createSigner

  public PrivateKey getKey() {
    return keypairWithCert.getKey();
  }

}
