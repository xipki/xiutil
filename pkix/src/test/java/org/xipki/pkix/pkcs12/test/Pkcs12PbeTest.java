// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12.test;

import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.asn1.pkcs12.PKCS12PBEParams;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PBMAC1Params;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.crypto.api.AlgorithmNames;
import org.xipki.pkix.pkcs12.Pkcs12Pbe;
import org.xipki.util.misc.RandomUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

/**
 * Tests {@link Pkcs12Pbe} against the PKCS#12 implementation of BouncyCastle.
 *
 * @author Lijun Liao (xipki)
 */
public class Pkcs12PbeTest {

  private static final String BC = "BC";

  private static final SecureRandom RND = RandomUtil.random();

  private static final Asn1Oid[] CIPHERS = {
      PkcsOIDs.pbeWithSHAAnd128BitRC4, PkcsOIDs.pbeWithSHAAnd40BitRC4,
      PkcsOIDs.pbeWithSHAAnd3_KeyTripleDES_CBC, PkcsOIDs.pbeWithSHAAnd2_KeyTripleDES_CBC,
      PkcsOIDs.pbeWithSHAAnd128BitRC2_CBC, PkcsOIDs.pbeWithSHAAnd40BitRC2_CBC};

  /**
   * The legacy ciphers RC2 and RC4, which a backend may not support (e.g. OpenSSL 3.x / 4.x
   * without the legacy provider).
   */
  private static final Set<Asn1Oid> LEGACY_CIPHERS = Set.of(
      PkcsOIDs.pbeWithSHAAnd128BitRC4, PkcsOIDs.pbeWithSHAAnd40BitRC4,
      PkcsOIDs.pbeWithSHAAnd128BitRC2_CBC, PkcsOIDs.pbeWithSHAAnd40BitRC2_CBC);

  private static final Set<Asn1Oid> BC_MAC_DIGESTS = Set.of(
      OiwOIDs.idSHA1, NistOIDs.id_sha256);

  @BeforeClass
  public static void init() {
    if (Security.getProvider(BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void testCiphers() throws Exception {
    char[][] passwords = {"1234".toCharArray(), "pässwörd-€".toCharArray()};
    for (Asn1Oid oid : CIPHERS) {
      if (LEGACY_CIPHERS.contains(oid) && !isSupported(oid)) {
        System.out.println("skipped " + oid.getId() + ": not supported by the crypto backend");
        continue;
      }

      for (char[] password : passwords) {
        for (int dataLen : new int[]{0, 7, 8, 100}) {
          byte[] salt = new byte[20];
          RND.nextBytes(salt);
          byte[] data = new byte[dataLen];
          RND.nextBytes(data);
          int iterations = 1000 + RND.nextInt(100);

          AlgorithmIdentifier algId = AlgorithmIdentifier.build(oid,
              new PKCS12PBEParams(salt, iterations));

          Cipher ours = Pkcs12Pbe.createCipher(Cipher.ENCRYPT_MODE, password, algId, false);
          byte[] encrypted = ours.doFinal(data);

          SecretKeyFactory kf = SecretKeyFactory.getInstance(oid.getId(), BC);
          Cipher bc = Cipher.getInstance(oid.getId(), BC);
          bc.init(Cipher.DECRYPT_MODE, kf.generateSecret(new PBEKeySpec(password)),
              new PBEParameterSpec(salt, iterations));
          Assert.assertArrayEquals(oid.getId(), data, bc.doFinal(encrypted));

          Cipher ours2 = Pkcs12Pbe.createCipher(Cipher.DECRYPT_MODE, password, algId, false);
          Assert.assertArrayEquals(oid.getId(), data, ours2.doFinal(encrypted));
        }
      }
    }
  }

  /** Returns whether the crypto backend supports the PKCS#12 PBE cipher. */
  private static boolean isSupported(Asn1Oid oid) throws Exception {
    AlgorithmIdentifier algId = AlgorithmIdentifier.build(oid,
        new PKCS12PBEParams(new byte[20], 1000));
    try {
      Pkcs12Pbe.createCipher(Cipher.ENCRYPT_MODE, "1234".toCharArray(), algId, false);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  @Test
  public void testCipherWrongZero() throws Exception {
    byte[] salt = new byte[8];
    RND.nextBytes(salt);
    byte[] data = "hello".getBytes();
    for (boolean wrongZero : new boolean[]{false, true}) {
      Asn1Oid oid = PkcsOIDs.pbeWithSHAAnd3_KeyTripleDES_CBC;
      AlgorithmIdentifier algId = AlgorithmIdentifier.build(oid, new PKCS12PBEParams(salt, 2048));

      byte[] encrypted = Pkcs12Pbe.createCipher(Cipher.ENCRYPT_MODE, new char[0], algId,
          wrongZero).doFinal(data);

      Cipher bc = Cipher.getInstance(oid.getId(), BC);
      bc.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(new char[0], wrongZero, salt, 2048));
      Assert.assertArrayEquals("wrongZero=" + wrongZero, data, bc.doFinal(encrypted));
    }
  }

  @Test
  public void testMac() throws Exception {
    Asn1Oid[] digests = {OiwOIDs.idSHA1, NistOIDs.id_sha224, NistOIDs.id_sha256,
        NistOIDs.id_sha384, NistOIDs.id_sha512};
    char[][] passwords = {"1234".toCharArray(), new char[0]};
    for (Asn1Oid digest : digests) {
      for (char[] password : passwords) {
        for (boolean wrongZero : new boolean[]{false, true}) {
          byte[] salt = new byte[16];
          RND.nextBytes(salt);
          byte[] data = new byte[333];
          RND.nextBytes(data);

          byte[] ours = Pkcs12Pbe.calculatePbeMac(AlgorithmIdentifier.ofNullParams(digest),
              salt, 2048, password, wrongZero, data);

          // BouncyCastle supports the PKCS#12 MAC by OID not for all digests
          Mac bcMac = null;
          try {
            bcMac = Mac.getInstance(digest.getId(), BC);
          } catch (NoSuchAlgorithmException e) {
            Assert.assertFalse(digest.getId(), BC_MAC_DIGESTS.contains(digest));
          }

          if (bcMac != null) {
            bcMac.init(new PKCS12Key(password, wrongZero), new PBEParameterSpec(salt, 2048));
            Assert.assertArrayEquals(digest.getId() + ", wrongZero=" + wrongZero,
                bcMac.doFinal(data), ours);
          }

          // the JDK supports neither empty passwords nor the wrong zero conversion
          if (password.length > 0) {
            String jdkName = "HmacPBE" + AlgorithmNames.getDigestName(digest).replace("-", "");
            Mac mac = Mac.getInstance(jdkName, "SunJCE");
            mac.init(new PBEKey(password), new PBEParameterSpec(salt, 2048));
            Assert.assertArrayEquals(jdkName, mac.doFinal(data), ours);
          }
        }
      }
    }
  }

  private static final class PBEKey implements javax.crypto.interfaces.PBEKey {

    private final char[] password;

    PBEKey(char[] password) {
      this.password = password;
    }

    @Override
    public char[] getPassword() {
      return password.clone();
    }

    @Override
    public byte[] getSalt() {
      return null;
    }

    @Override
    public int getIterationCount() {
      return 0;
    }

    @Override
    public String getAlgorithm() {
      return "PBE";
    }

    @Override
    public String getFormat() {
      return "RAW";
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }

  }

  @Test
  public void testPbmac1() throws Exception {
    byte[] salt = new byte[16];
    RND.nextBytes(salt);
    byte[] data = new byte[100];
    RND.nextBytes(data);
    char[] password = "1234".toCharArray();

    AlgorithmIdentifier prf = AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256);
    PBKDF2Params kdfParams = new PBKDF2Params(salt, 4096, 32, prf);
    AlgorithmIdentifier macAlg = AlgorithmIdentifier.build(PkcsOIDs.id_PBMAC1,
        new PBMAC1Params(AlgorithmIdentifier.build(PkcsOIDs.id_PBKDF2, kdfParams),
            AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA512)));

    byte[] ours = Pkcs12Pbe.calculatePbeMac(macAlg, null, 0, password, false, data);

    byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", BC)
        .generateSecret(new PBEKeySpec(password, salt, 4096, 256)).getEncoded();
    Mac mac = Mac.getInstance("HmacSHA512", BC);
    mac.init(new SecretKeySpec(key, "HmacSHA512"));
    Assert.assertArrayEquals(mac.doFinal(data), ours);
  }

}
