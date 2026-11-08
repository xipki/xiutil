// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.KemEncapsulation;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.crypto.core.SecretKeyWithAlias;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

/**
 * @author Lijun Liao (xipki)
 */
public class KemMacTest {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  @Test
  public void signVerify() throws Exception {
    // only the verifier has the master key
    String alias = "alias";
    SecretKeySpec masterKey0 = new SecretKeySpec(new byte[32], "AES");
    SecretKeyWithAlias masterKey = new SecretKeyWithAlias(alias, masterKey0);

    // Sender: generates keypair
    KeyPairGenerator kpGen = cryptoApi.newKeyPairGenerator("ML-KEM-512");
    KeyPair myKeyPair = kpGen.generateKeyPair();

    SubjectPublicKeyInfo myPkInfo = SubjectPublicKeyInfo.fromPublicKey(myKeyPair.getPublic());

    // Receiver: generates encapsulated MAC key
    KemEncapKey kemEncapKey = KemUtil.generateKemEncapKey(myPkInfo, masterKey);

    // Sender: decrypts the mac key using private key
    byte[] macKeyBytes;
    {
      byte alg = kemEncapKey.encapulation().alg();
      if (alg != KemEncapsulation.ALG_KMAC_MLKEM_HMAC) {
        throw new XiSecurityException("unknown wrap mechanism " + alg);
      }

      macKeyBytes = KemUtil.mlkemDecryptSecret(myKeyPair.getPrivate(),
          kemEncapKey.encapulation());
    }

    // Sender: compute the HMAC value
    byte[] data = new byte[100];
    byte[] sig;
    {
      SecretKey macKey = new SecretKeySpec(macKeyBytes, "AES");
      Mac mac = cryptoApi.newMac("HMAC-SHA256");
      mac.init(macKey);
      mac.update(data);
      byte[] rawSignature = mac.doFinal();

      Asn1Utf8String utf8Id = new Asn1Utf8String(kemEncapKey.id());
      sig = new Asn1Sequence(utf8Id, new Asn1OctetString(rawSignature)).getEncoded();
    }

    // Verifier: verify the mac value
    {
      Asn1Sequence seq = Asn1Sequence.fromEncoded(sig);
      // id: will be used to identify the mackey. not used currently.
      // ASN1UTF8String id = seq.getUtf8StringAt(0);
      byte[] rawSignature = seq.getOctetStringAt(1).getOctets();

      byte[] rawPkData = myPkInfo.subjectPublicKey();
      byte[] secret = KemUtil.hmacDerive(masterKey.secretKey(), 32,
          "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);

      SecretKey macKey = new SecretKeySpec(secret, "AES");
      HmacSigner verifier = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
      byte[] macValue = verifier.contentSigner().atomicSign(data);
      boolean valid = Arrays.equals(rawSignature, macValue);
      Assert.assertTrue("signature invalid", valid);
    }

  }

}
