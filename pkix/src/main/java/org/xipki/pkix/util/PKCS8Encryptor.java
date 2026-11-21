// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.EncryptedPrivateKeyInfo;
import org.xipki.codec.x509.PBES2Parameters;
import org.xipki.codec.x509.PBKDF2Params;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.x509.id.NistOIDs;
import org.xipki.codec.x509.id.PkcsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Encrypts a PKCS#8 private key with PBES2 (RFC 8018): PBKDF2 with HMAC-SHA256 and AES-256-CBC,
 * the scheme of {@code openssl pkcs8 -topk8} since OpenSSL 1.1.0. The password is converted to
 * bytes with UTF-8, as OpenSSL does.
 *
 * @author Lijun Liao (xipki)
 */
public final class PKCS8Encryptor {

  private static final CryptoApi crypto = CryptoApiFactory.get();

  private static final int SALT_SIZE = 16;

  private static final int ITERATION_COUNT = 300000;

  private static final int KEY_SIZE = 32;

  private PKCS8Encryptor() {
  }

  public static EncryptedPrivateKeyInfo encrypt(
      PrivateKeyInfo key, char[] password) throws GeneralSecurityException {
    Args.notNull(key, "key");
    Args.notNull(password, "password");

    byte[] salt = new byte[SALT_SIZE];
    crypto.getSecureRandom().nextBytes(salt);
    byte[] iv = new byte[16];
    crypto.getSecureRandom().nextBytes(iv);

    AlgorithmIdentifier prf = AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256);
    AlgorithmIdentifier kdf = AlgorithmIdentifier.build(PkcsOIDs.id_PBKDF2,
        new PBKDF2Params(salt, ITERATION_COUNT, prf));
    AlgorithmIdentifier enc = new AlgorithmIdentifier(NistOIDs.id_aes256_CBC,
        new Asn1OctetString(iv));
    AlgorithmIdentifier algId = AlgorithmIdentifier.build(PkcsOIDs.id_PBES2,
        new PBES2Parameters(kdf, enc));

    byte[] keyBytes = crypto.pbkdf2(prf, password, salt, ITERATION_COUNT, KEY_SIZE);
    byte[] encoded = key.getEncoded();
    try {
      Cipher cipher = crypto.newCipher("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
          new IvParameterSpec(iv), crypto.getSecureRandom());
      return new EncryptedPrivateKeyInfo(algId, cipher.doFinal(encoded));
    } finally {
      XiArrays.clear(keyBytes);
      XiArrays.clear(encoded);
    }
  }

}
