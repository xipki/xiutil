// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.SecurityFactoryImpl;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.DHSigStaticKeyCertPair;
import org.xipki.pkix.sign.XDHContentVerifierFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies the DH-PoP (RFC 6955, sa-ecdhPop-sha*-hmac-sha*) signatures of the C509 type 2
 * certification requests of draft-ietf-cose-c509-test-vectors-05 (repository
 * id-c509-cert-test-vectors, folder test-vectors-05) as the peer (CA).
 *
 * <p>The peer certificate selfsign-secp384r1 of dhsig-sha384 contains an extendedKeyUsage
 * with an OID, which pkix-cbor does not parse; of it only the issuer, serial number and subject
 * are read.
 *
 * @author Lijun Liao (xipki)
 */
public class C509DhPopTestVectorsTest {

  private static final String BASE = "/c509-test-vectors-05/";

  @Test
  public void dhsigSha256() throws Exception {
    verifyWithSecurityFactory("dhsig-sha256", "cert/selfsign-secp256r1", "secp256r1");
  }

  @Test
  public void dhsigSha384() throws Exception {
    String name = "dhsig-sha384";
    C509CertificationRequest csr = parseCsr(name);
    DHSigStaticKeyCertPair owner = rawOwner(
        readPrivateKey("secp384r1"), read("peer/selfsign-secp384r1/c509cert-t2.bin"));
    PublicKey subjectKey = KeyInfoUtil.getPublicKey(csr.subjectPublicKey());

    Assert.assertTrue(name + ": valid POP",
        csr.verify(new XDHContentVerifierFactory(subjectKey, owner)));
    Assert.assertFalse(name + ": POP over other data", tampered(csr).verify(
        new XDHContentVerifierFactory(subjectKey, owner)));
  }

  @Test
  public void dhsigSha512() throws Exception {
    verifyWithSecurityFactory("dhsig-sha512", "cert/selfsign-secp521r1", "secp521r1");
  }

  private static void verifyWithSecurityFactory(String name, String peerCert, String peerKey)
      throws Exception {
    C509CertificationRequest csr = parseCsr(name);
    C509Cert cert = new C509Cert(C509Certificate.parse(read(peerCert + "/c509cert-t2.bin")));
    DHSigStaticKeyCertPair.C509 owner =
        new DHSigStaticKeyCertPair.C509(readPrivateKey(peerKey), cert);

    SecurityFactoryImpl securityFactory = new SecurityFactoryImpl();
    Assert.assertTrue(name + ": valid POP", securityFactory.verifyPop(csr, null, owner, null));
    Assert.assertFalse(name + ": POP over other data",
        securityFactory.verifyPop(tampered(csr), null, owner, null));
    Assert.assertFalse(name + ": POP without ownerKeyAndCert",
        securityFactory.verifyPop(csr, null, null, null));
  }

  /**
   * Returns the request with the subject name (the name of the test vector) changed, and the
   * signature value unchanged.
   */
  private static C509CertificationRequest tampered(C509CertificationRequest csr)
      throws Exception {
    byte[] encoded = csr.getEncoded();
    String subject = csr.subject().getNameText();
    int off = indexOf(encoded, subject.substring(subject.indexOf('=') + 1)
        .getBytes(StandardCharsets.UTF_8));
    encoded[off] ^= 0x20; // lower case to upper case
    return C509CertificationRequest.parse(encoded);
  }

  private static int indexOf(byte[] data, byte[] part) {
    outer:
    for (int i = 0; i <= data.length - part.length; i++) {
      for (int j = 0; j < part.length; j++) {
        if (data[i + j] != part[j]) {
          continue outer;
        }
      }
      return i;
    }
    throw new IllegalArgumentException("part not found");
  }

  /**
   * Builds the owner's key and certificate from the issuer, serial number and subject of a type 2
   * certificate, without parsing the whole certificate. An absent issuer is the subject.
   */
  private static DHSigStaticKeyCertPair rawOwner(PrivateKey key, byte[] cert) throws Exception {
    CborDecoder in = new ByteArrayCborDecoder(cert);
    in.readArrayLength();
    in.readEncodedItem(); // type
    BigInteger serial = new BigInteger(1, in.readByteString());
    in.readEncodedItem(); // signature algorithm
    byte[] issuer = in.readEncodedItem().getEncoded();
    in.readEncodedItem(); // notBefore
    in.readEncodedItem(); // notAfter
    byte[] subject = C509Name.read(in).getEncoded();
    byte[] effectiveIssuer = (issuer.length == 1 && issuer[0] == (byte) 0xF6) ? subject : issuer;

    return new DHSigStaticKeyCertPair(key, serial) {
      @Override
      public byte[] encodedIssuer() {
        return effectiveIssuer.clone();
      }

      @Override
      public byte[] encodedSubject() {
        return subject.clone();
      }
    };
  }

  private static C509CertificationRequest parseCsr(String name) throws Exception {
    return C509CertificationRequest.parse(read("csr/" + name + "/c509csr-t2.bin"));
  }

  private static PrivateKey readPrivateKey(String name) throws Exception {
    String pem = new String(read("key/" + name + "/prikey.pem"), StandardCharsets.US_ASCII);
    String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    return KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
  }

  private static byte[] read(String path) throws IOException {
    try (InputStream in = C509DhPopTestVectorsTest.class.getResourceAsStream(BASE + path)) {
      if (in == null) {
        throw new IOException("resource not found: " + BASE + path);
      }
      return in.readAllBytes();
    }
  }

}
