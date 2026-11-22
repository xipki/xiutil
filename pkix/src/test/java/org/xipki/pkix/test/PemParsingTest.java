// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.test;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.Base64;
import org.xipki.pkix.util.C509Util;
import org.xipki.pkix.util.X509Util;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;

/**
 * Test of the PEM / base64 / DER detection in {@link X509Util#toDerEncoded(byte[])} and the
 * certificate parsers with short and malformed input.
 *
 * @author Lijun Liao (xipki)
 */
public class PemParsingTest {

  private static byte[] der;

  @BeforeClass
  public static void init() throws Exception {
    try (InputStream in = PemParsingTest.class.getResourceAsStream("/keycerts/tls-c1.crt")) {
      der = in.readAllBytes();
    }
  }

  @Test
  public void derIsUnchanged() {
    Assert.assertArrayEquals(der, X509Util.toDerEncoded(der));
  }

  @Test
  public void pemIsDecoded() {
    Assert.assertArrayEquals(der, X509Util.toDerEncoded(pem("\n")));
    Assert.assertArrayEquals(der, X509Util.toDerEncoded(pem("\r\n")));
  }

  @Test
  public void base64IsDecoded() {
    Assert.assertArrayEquals(der, X509Util.toDerEncoded(ascii(Base64.encodeToString(der))));
  }

  @Test
  public void shortInputIsUnchanged() {
    for (String s : new String[]{"", "A", "-----BEG", "AAAA", "-----BEGIN"}) {
      byte[] bytes = ascii(s);
      Assert.assertArrayEquals(s, bytes, X509Util.toDerEncoded(bytes));
    }
  }

  @Test
  public void malformedPemIsUnchanged() {
    String body = Base64.encodeToString(der);
    String[] inputs = {
        // no separator after BEGIN
        "-----BEGIN CERTIFICATE without separator",
        // header ends with the end of the input
        "-----BEGIN CERTIFICATE-----",
        // no END line
        "-----BEGIN CERTIFICATE-----\n" + body + "\n",
        // END line before the base64 start
        "-----BEGIN -----END CERTIFICATE-----\n" + body,
        // invalid base64 content
        "-----BEGIN CERTIFICATE-----\n!!!!" + body + "\n-----END CERTIFICATE-----\n",
        // only the first 10 chars are valid base64
        "AAAAAAAAAA!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"};
    for (String s : inputs) {
      byte[] bytes = ascii(s);
      Assert.assertArrayEquals(s, bytes, X509Util.toDerEncoded(bytes));
    }
  }

  @Test
  public void parseCertRejectsInvalidInput() throws Exception {
    Assert.assertEquals(X509Util.parseCert(der), X509Util.parseCert(pem("\n")));

    String[] inputs = {"", "A", "-----BEG", "AAAA", "-----BEGIN",
        "-----BEGIN CERTIFICATE-----", "AAAAAAAAAA!!!!!!!!!!!!!!!!!!!!!!!!!"};
    for (String s : inputs) {
      byte[] bytes = ascii(s);
      Assert.assertThrows("X509: '" + s + "'", CertificateEncodingException.class,
          () -> X509Util.parseCert(bytes));
      Assert.assertThrows("C509: '" + s + "'", CertificateEncodingException.class,
          () -> C509Util.parseCert(bytes));
    }
  }

  private static byte[] pem(String lineEnd) {
    String body = Base64.encodeToString(der, true).replace("\r\n", "\n").replace("\n", lineEnd);
    return ascii("-----BEGIN CERTIFICATE-----" + lineEnd + body + lineEnd
        + "-----END CERTIFICATE-----" + lineEnd);
  }

  private static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }

}
