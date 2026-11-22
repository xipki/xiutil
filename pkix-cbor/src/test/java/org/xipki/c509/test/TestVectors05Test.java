// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.csrt.C509CertificationRequestTemplate;
import org.xipki.codec.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The C509 type 2 (natively signed) certificates, certification requests and certification
 * request templates of draft-ietf-cose-c509-test-vectors-05 (repository
 * id-c509-cert-test-vectors, folder test-vectors-05).
 *
 * <p>Only the vectors are used whose attributes, RDN attributes, extensions, policy IDs and
 * extended key usages, if present, are identified by integers. The following vectors are
 * therefore not included:
 * <ul>
 *   <li>cert/selfsign-brainpoolp512r1: policyMappings with OID policy IDs</li>
 *   <li>cert/selfsign-secp384r1: extendedKeyUsage with an OID</li>
 *   <li>csrt/complex-csrt: RDN attributes and extensions identified by OIDs</li>
 * </ul>
 * Also not included:
 * <ul>
 *   <li>cert/ee-x25519: authorityInfoAccess with an OID access method, not supported</li>
 *   <li>csr/ecdsa-p384: challengePassword as a tagged Printable String, which is not allowed
 *       in a type 2 certification request</li>
 * </ul>
 * The DH-PoP signatures of the certification requests dhsig-sha* are verified in the module
 * pkix (C509DhPopTestVectorsTest), here they are only parsed.
 *
 * @author Lijun Liao (xipki)
 */
public class TestVectors05Test {

  private static final String BASE = "/c509-test-vectors-05/";

  private static final String[] CERTS = {
      "8byte-id", "ca", "crl-signer", "ee-x448", "ocsp-requestor", "ocsp-responder",
      "selfsign-brainpoolp256r1", "selfsign-brainpoolp384r1", "selfsign-compress-secp256r1",
      "selfsign-ecdsa-with-sha1", "selfsign-ed25519", "selfsign-ed448", "selfsign-frp256v1",
      "selfsign-rsa", "selfsign-rsa-f5", "selfsign-rsa-with-sha1", "selfsign-rsa-with-sha384",
      "selfsign-rsa-with-sha512", "selfsign-rsassa-pss-sha256", "selfsign-rsassa-pss-sha384",
      "selfsign-rsassa-pss-sha512", "selfsign-rsassa-pss-shake128",
      "selfsign-rsassa-pss-shake256", "selfsign-secp256r1", "selfsign-secp521r1",
      "selfsign-sm2p256v1", "selfsign-wisun-br", "selfsign-wisun-device",
      "simple-selfsign-ed25519"};

  /** Certificates whose curve is not supported by the crypto backend: parsed only. */
  private static final Set<String> NO_SIGNATURE_CHECK = Set.of("selfsign-frp256v1");

  /** Certification requests signed with the subject's own signature key. */
  private static final String[] CSRS = {
      "8byte-id", "ecdsa-p256", "x25519", "x25519-withcert"};

  /** DH-PoP certification requests: parsed only. */
  private static final String[] DHSIG_CSRS = {"dhsig-sha256", "dhsig-sha384", "dhsig-sha512"};

  private static final String[] CSRTS = {"8byte-id-csrt", "oneelement-csrt", "undefined-csrt"};

  @Test
  public void certificates() throws Exception {
    C509Certificate ca = parseCert("cert/ca");
    List<String> failures = new ArrayList<>();
    for (String name : CERTS) {
      try {
        byte[] encoded = read("cert/" + name + "/c509cert-t2.bin");
        C509Certificate cert = C509Certificate.parse(encoded);
        Assert.assertEquals(name + ": type", 2, cert.type());
        Assert.assertEquals(name + ": re-encoded", Hex.encode(encoded),
            Hex.encode(cert.getEncoded()));

        C509Certificate issuer = cert.isSelfSigned() ? cert : ca;
        Assert.assertEquals(name + ": issuer", issuer.body().subject(), cert.issuer());
        if (NO_SIGNATURE_CHECK.contains(name)) {
          continue;
        }
        PublicKey issuerKey = TestKeys.toJca(issuer.body().subjectPublicKey());
        Assert.assertTrue(name + ": signature",
            cert.verify(new TestKeys.MyContentVerifierFactory(issuerKey)));
      } catch (Throwable t) {
        failures.add(name + ": " + t);
      }
    }
    assertNoFailures(failures);
  }

  @Test
  public void certificationRequests() throws Exception {
    List<String> failures = new ArrayList<>();
    for (String name : CSRS) {
      try {
        C509CertificationRequest csr = parseCsr(name);
        PublicKey key = TestKeys.toJca(csr.subjectPublicKey());
        Assert.assertTrue(name + ": signature",
            csr.verify(new TestKeys.MyContentVerifierFactory(key)));
      } catch (Throwable t) {
        failures.add(name + ": " + t);
      }
    }
    assertNoFailures(failures);
  }

  @Test
  public void dhPopCertificationRequests() throws Exception {
    List<String> failures = new ArrayList<>();
    for (String name : DHSIG_CSRS) {
      try {
        parseCsr(name);
      } catch (Throwable t) {
        failures.add(name + ": " + t);
      }
    }
    assertNoFailures(failures);
  }

  @Test
  public void certificationRequestTemplates() throws Exception {
    List<String> failures = new ArrayList<>();
    for (String name : CSRTS) {
      try {
        byte[] encoded = read("csrt/" + name + "/c509csrt.bin");
        C509CertificationRequestTemplate csrt = C509CertificationRequestTemplate.parse(encoded);
        Assert.assertEquals(name + ": re-encoded", Hex.encode(encoded),
            Hex.encode(csrt.getEncoded()));
      } catch (Throwable t) {
        failures.add(name + ": " + t);
      }
    }
    assertNoFailures(failures);
  }

  private static void assertNoFailures(List<String> failures) {
    if (!failures.isEmpty()) {
      Assert.fail(failures.size() + " failure(s):\n  " + String.join("\n  ", failures));
    }
  }

  private static C509Certificate parseCert(String dir) throws Exception {
    return C509Certificate.parse(read(dir + "/c509cert-t2.bin"));
  }

  private static C509CertificationRequest parseCsr(String name) throws Exception {
    byte[] encoded = read("csr/" + name + "/c509csr-t2.bin");
    C509CertificationRequest csr = C509CertificationRequest.parse(encoded);
    Assert.assertEquals(name + ": type", 2, csr.type());
    Assert.assertEquals(name + ": re-encoded", Hex.encode(encoded),
        Hex.encode(csr.getEncoded()));
    return csr;
  }

  private static byte[] read(String path) throws IOException {
    try (InputStream in = TestVectors05Test.class.getResourceAsStream(BASE + path)) {
      if (in == null) {
        throw new IOException("resource not found: " + BASE + path);
      }
      return in.readAllBytes();
    }
  }

}
