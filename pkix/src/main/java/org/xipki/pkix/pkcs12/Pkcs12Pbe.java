// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.asn1.pkcs12.PKCS12PBEParams;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PBMAC1Params;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.util.XiArrays;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.AlgorithmNames;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Password-based encryption and MAC of PKCS#12 (RFC 7292, Appendix B and C), and PBMAC1
 * (RFC 9579). Only standard JCA primitives (digest, HMAC, cipher) of the crypto backend are used.
 *
 * @author Lijun Liao (xipki)
 */
public final class Pkcs12Pbe {

  private static final CryptoApi crypto = CryptoApiFactory.get();

  private static final int ID_KEY = 1;

  private static final int ID_IV = 2;

  private static final int ID_MAC = 3;

  /**
   * PKCS#12 PBE cipher algorithms: OID to {transformation, key size in bytes, IV size in
   * bytes}.
   */
  private static final Map<Asn1Oid, Object[]> CIPHERS = new HashMap<>();

  /**
   * MAC digest algorithms: OID to {digest name, HMAC name, digest length, block length}.
   */
  private static final Map<Asn1Oid, Object[]> MAC_DIGESTS = new HashMap<>();

  static {
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd128BitRC4, new Object[]{"ARCFOUR", 16, 0});
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd40BitRC4, new Object[]{"ARCFOUR", 5, 0});
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd3_KeyTripleDES_CBC,
        new Object[]{"DESede/CBC/PKCS5Padding", 24, 8});
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd2_KeyTripleDES_CBC,
        new Object[]{"DESede/CBC/PKCS5Padding", 16, 8});
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd128BitRC2_CBC, new Object[]{"RC2/CBC/PKCS5Padding", 16, 8});
    CIPHERS.put(PkcsOIDs.pbeWithSHAAnd40BitRC2_CBC, new Object[]{"RC2/CBC/PKCS5Padding", 5, 8});

    MAC_DIGESTS.put(OiwOIDs.idSHA1,          new Object[]{"SHA-1",       "HmacSHA1",   20,  64});
    MAC_DIGESTS.put(NistOIDs.id_sha224,      new Object[]{"SHA-224",     "HmacSHA224", 28,  64});
    MAC_DIGESTS.put(NistOIDs.id_sha256,      new Object[]{"SHA-256",     "HmacSHA256", 32,  64});
    MAC_DIGESTS.put(NistOIDs.id_sha384,      new Object[]{"SHA-384",     "HmacSHA384", 48, 128});
    MAC_DIGESTS.put(NistOIDs.id_sha512,      new Object[]{"SHA-512",     "HmacSHA512", 64, 128});
    MAC_DIGESTS.put(NistOIDs.id_sha512_224,
        new Object[]{"SHA-512/224", "HmacSHA512/224", 28, 128});
    MAC_DIGESTS.put(NistOIDs.id_sha512_256,
        new Object[]{"SHA-512/256", "HmacSHA512/256", 32, 128});
  }

  private Pkcs12Pbe() {
  }

  /**
   * Creates the cipher for a PKCS#12 PBE algorithm (OID under 1.2.840.113549.1.12.1).
   *
   * @param mode the cipher mode, e.g. {@link Cipher#ENCRYPT_MODE}.
   * @param password the password.
   * @param algId the algorithm with {@link PKCS12PBEParams} as parameters.
   * @param wrongPKCS12Zero whether an empty password is converted to two zero bytes instead
   *        of an empty byte array (bug of some old implementations).
   * @return the initialized cipher.
   * @throws GeneralSecurityException if the algorithm is not supported.
   */
  public static Cipher createCipher(
      int mode, char[] password, AlgorithmIdentifier algId, boolean wrongPKCS12Zero)
      throws GeneralSecurityException {
    Object[] params = CIPHERS.get(algId.getAlgorithm());
    if (params == null) {
      throw new NoSuchAlgorithmException("unsupported PKCS#12 PBE algorithm "
          + algId.getAlgorithm().getId());
    }

    PKCS12PBEParams pbeParams;
    try {
      pbeParams = PKCS12PBEParams.fromAsn1(algId.getParameters().asSequence());
    } catch (CodecException e) {
      throw new NoSuchAlgorithmException("could not parse PKCS12PBEParams", e);
    }

    String transformation = (String) params[0];
    int keySize = (int) params[1];
    int ivSize = (int) params[2];

    byte[] pwd = passwordToBytes(password, wrongPKCS12Zero);
    byte[] salt = pbeParams.salt();
    int iterations = pbeParams.iterations();

    byte[] key = deriveKey("SHA-1", 20, 64, pwd, salt, iterations, ID_KEY, keySize);
    byte[] iv = ivSize == 0 ? null
        : deriveKey("SHA-1", 20, 64, pwd, salt, iterations, ID_IV, ivSize);
    XiArrays.clear(pwd);

    String keyAlg;
    AlgorithmParameterSpec paramSpec;
    if (transformation.startsWith("DESede")) {
      keyAlg = "DESede";
      if (keySize == 16) {
        // two-key triple DES: K1 || K2 || K1
        byte[] key3 = new byte[24];
        System.arraycopy(key, 0, key3, 0, 16);
        System.arraycopy(key, 0, key3, 16, 8);
        XiArrays.clear(key);
        key = key3;
      }
      paramSpec = new IvParameterSpec(iv);
    } else if (transformation.startsWith("RC2")) {
      keyAlg = "RC2";
      paramSpec = new RC2ParameterSpec(keySize * 8, iv);
    } else {
      keyAlg = "ARCFOUR";
      paramSpec = null;
    }

    Cipher cipher = crypto.newCipher(transformation);
    SecretKeySpec secretKey = new SecretKeySpec(key, keyAlg);
    XiArrays.clear(key);
    if (paramSpec == null) {
      cipher.init(mode, secretKey, crypto.getSecureRandom());
    } else {
      cipher.init(mode, secretKey, paramSpec, crypto.getSecureRandom());
    }
    return cipher;
  }

  /**
   * Calculates the MAC of a PKCS#12 PFX (RFC 7292, Appendix B), or PBMAC1 (RFC 9579).
   *
   * @param macAlgorithm the digest algorithm of the MacData, or PBMAC1.
   * @param salt the salt of the MacData, ignored for PBMAC1.
   * @param itCount the iteration count of the MacData, ignored for PBMAC1.
   * @param password the password.
   * @param wrongPKCS12Zero whether an empty password is converted to two zero bytes.
   * @param data the data.
   * @return the MAC.
   * @throws GeneralSecurityException if the algorithm is not supported.
   */
  public static byte[] calculatePbeMac(
      AlgorithmIdentifier macAlgorithm, byte[] salt, int itCount,
      char[] password, boolean wrongPKCS12Zero, byte[] data) throws GeneralSecurityException {
    Asn1Oid oid = macAlgorithm.getAlgorithm();
    if (PkcsOIDs.id_PBMAC1.equals(oid)) {
      return calculatePbmac1(macAlgorithm, password, data);
    }

    Object[] params = MAC_DIGESTS.get(oid);
    if (params == null) {
      throw new NoSuchAlgorithmException("unsupported PKCS#12 MAC digest " + oid.getId());
    }

    byte[] pwd = passwordToBytes(password, wrongPKCS12Zero);
    int digestLen = (int) params[2];
    byte[] key = deriveKey((String) params[0], digestLen, (int) params[3],
        pwd, salt, itCount, ID_MAC, digestLen);
    XiArrays.clear(pwd);
    return hmac((String) params[1], key, data);
  }

  private static byte[] calculatePbmac1(
      AlgorithmIdentifier macAlgorithm, char[] password, byte[] data)
      throws GeneralSecurityException {
    PBMAC1Params pbmac1Params;
    PBKDF2Params pbkdf2Params;
    try {
      pbmac1Params = PBMAC1Params.fromAsn1(macAlgorithm.getParameters().asSequence());
      AlgorithmIdentifier kdf = pbmac1Params.getKeyDerivationFunc();
      if (!PkcsOIDs.id_PBKDF2.equals(kdf.getAlgorithm())) {
        throw new NoSuchAlgorithmException("unsupported PBMAC1 key derivation function "
            + kdf.getAlgorithm().getId());
      }
      pbkdf2Params = PBKDF2Params.fromAsn1(kdf.getParameters().asSequence());
    } catch (CodecException e) {
      throw new GeneralSecurityException("could not parse PBMAC1Params", e);
    }

    if (pbkdf2Params.keyLength() == null) {
      throw new GeneralSecurityException("Key length must be present when using PBMAC1.");
    }

    Asn1Oid macOid = pbmac1Params.getMessageAuthScheme().getAlgorithm();
    String hmacName = AlgorithmNames.getHmacName(macOid);
    if (hmacName == null) {
      throw new NoSuchAlgorithmException("unsupported PBMAC1 MAC " + macOid.getId());
    }

    byte[] key = crypto.pbkdf2(pbkdf2Params.getPrf(), password, pbkdf2Params.salt(),
        pbkdf2Params.iterationCount(), pbkdf2Params.keyLength());
    return hmac(hmacName, key, data);
  }

  private static byte[] hmac(String hmacName, byte[] key, byte[] data)
      throws GeneralSecurityException {
    Mac mac = crypto.newMac(hmacName);
    mac.init(new SecretKeySpec(key, hmacName));
    XiArrays.clear(key);
    return mac.doFinal(data);
  }

  /**
   * Converts the password to a BMPString with two trailing zero bytes (RFC 7292, Appendix B.1).
   */
  static byte[] passwordToBytes(char[] password, boolean wrongPKCS12Zero) {
    if (password == null || password.length == 0) {
      return wrongPKCS12Zero ? new byte[2] : new byte[0];
    }

    byte[] bytes = new byte[(password.length + 1) * 2];
    for (int i = 0; i < password.length; i++) {
      bytes[i * 2] = (byte) (password[i] >>> 8);
      bytes[i * 2 + 1] = (byte) password[i];
    }
    return bytes;
  }

  /**
   * Derives key material with the PKCS#12 KDF (RFC 7292, Appendix B.2).
   *
   * @param digestName the digest name.
   * @param u the digest output length in bytes.
   * @param v the digest block length in bytes.
   * @param pwd the password bytes (see {@link #passwordToBytes(char[], boolean)}).
   * @param salt the salt.
   * @param iterations the iteration count.
   * @param id 1 for key, 2 for IV, 3 for MAC key.
   * @param n the number of bytes to derive.
   * @return the derived bytes.
   */
  static byte[] deriveKey(String digestName, int u, int v, byte[] pwd, byte[] salt,
                          int iterations, int id, int n) throws GeneralSecurityException {
    if (iterations < 1) {
      throw new GeneralSecurityException("invalid iteration count " + iterations);
    }

    MessageDigest md = crypto.newMessageDigest(digestName);

    byte[] d = new byte[v];
    Arrays.fill(d, (byte) id);

    byte[] s = fill(salt, v);
    byte[] p = fill(pwd, v);
    byte[] i = new byte[s.length + p.length];
    System.arraycopy(s, 0, i, 0, s.length);
    System.arraycopy(p, 0, i, s.length, p.length);
    XiArrays.clear(p);

    int c = (n + u - 1) / u;
    byte[] result = new byte[n];
    byte[] b = new byte[v];

    for (int k = 1; k <= c; k++) {
      md.update(d);
      md.update(i);
      byte[] a = md.digest();
      for (int it = 1; it < iterations; it++) {
        a = md.digest(a);
      }

      int len = Math.min(u, n - (k - 1) * u);
      System.arraycopy(a, 0, result, (k - 1) * u, len);

      if (k == c) {
        break;
      }

      for (int j = 0; j < v; j++) {
        b[j] = a[j % u];
      }

      // I_j = (I_j + B + 1) mod 2^(8v)
      for (int j = 0; j < i.length / v; j++) {
        int off = j * v;
        int carry = 1;
        for (int m = v - 1; m >= 0; m--) {
          int sum = (i[off + m] & 0xFF) + (b[m] & 0xFF) + carry;
          i[off + m] = (byte) sum;
          carry = sum >>> 8;
        }
      }
    }

    XiArrays.clear(i);
    return result;
  }

  private static byte[] fill(byte[] input, int v) {
    if (input == null || input.length == 0) {
      return new byte[0];
    }

    int len = v * ((input.length + v - 1) / v);
    byte[] res = new byte[len];
    for (int j = 0; j < len; j++) {
      res[j] = input[j % input.length];
    }
    return res;
  }

}
