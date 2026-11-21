// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.misc;

import org.xipki.codec.Base64;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.util.XiArrays;

import java.nio.charset.StandardCharsets;

/**
 * Pem Encoder.
 *
 * @author Lijun Liao (xipki)
 */
public class PemEncoder {

  /**
   * Pem Label enumeration.
   */
  public enum PemLabel {
    /**
     * RFC5280 Certificate.
     */
    CERTIFICATE("CERTIFICATE"),

    /**
     * RFC 5280 CertificateList.
     */
    X509_CRL("X509 CRL"),

    /**
     * RFC 2986 CertificationRequest.
     */
    CERTIFICATE_REQUEST("CERTIFICATE REQUEST"),

    /**
     * RFC 2315 ContentInfo.
     */
    PKCS7("PKCS7"),

    /**
     * RFC 5652 ContentInfo.
     */
    CMS("CMS"),

    /**
     * RFC 5208 PrivateKeyInfo / RFC 5958 OneAsymmetricKey.
     */
    PRIVATE_KEY("PRIVATE KEY"),

    /**
     * RFC 5958 EncryptedPrivateKeyInfo.
     */
    ENCRYPTED_PRIVATE_KEY("ENCRYPTED PRIVATE KEY"),

    /**
     * RFC 5755 AttributeCertificate.
     */
    ATTRIBUTE_CERTIFICATE("ATTRIBUTE CERTIFICATE"),

    /**
     * RFC 5280 SubjectPublicKeyInfo.
     */
    PUBLIC_KEY("PUBLIC KEY"),

    // C509: https://datatracker.ietf.org/doc/draft-liao-cose-c509-additions/
    //
    /**
     * C509 Certificate.
     */
    C509_CERTIFICATE("C509 CERTIFICATE"),

    /**
     * COSE_C509
     */
    COCE_C509("COSE C509"),

    /**
     * C509 CertificationRequest.
     */
    C509_CERTIFICATE_REQUEST("C509 CERTIFICATE REQUEST"),

    /**
     * C509 SubjectPublicKeyInfo.
     */
    C509_PUBLIC_KEY("C509 PUBLIC KEY"),

    /**
     * C509PrivateKey.
     */
    C509_PRIVATE_KEY("C509 PRIVATE KEY"),

    /**
     * C509PEM
     */
    C509_PEM("C509 PEM"),

    /**
     * C509 CertificateList.
     */
    C509_CRL("C509 CRL"),

    /**
     * C509 OCSP request.
     */
    C509_OCSP_REQUEST("C509 OCSP REQUEST"),

    /**
     * C509 OCSP response.
     */
    C509_OCSP_RESPONSE("C509 OCSP RESPONSE");

    private final byte[] prefix;

    private final byte[] postfix;

    private final String type;

    PemLabel(String type) {
      this.type = type;
      this.prefix = StringUtil.toUtf8Bytes(
          "-----BEGIN " + type + "-----\r\n");
      this.postfix = StringUtil.toUtf8Bytes(
          "\r\n-----END " + type + "-----\r\n");
    }

    public String type() {
      return type;
    }

  }

  public static byte[] encode(byte[] data, PemLabel pemLabel) {
    byte[] base64 = Base64.encodeToPemByte(data);
    return XiArrays.concatenate(pemLabel.prefix, base64, pemLabel.postfix);
  }

  public static byte[] encode(byte[] data, String type) {
    byte[] base64 = Base64.encodeToPemByte(data);
    byte[] prefix = ("-----BEGIN " + type + "-----\r\n").getBytes(StandardCharsets.UTF_8);
    byte[] suffix = ("\r\n-----END " + type + "-----\r\n").getBytes(StandardCharsets.UTF_8);
    return XiArrays.concatenate(prefix, base64, suffix);
  }

}
