// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * Certificate types, see the IANA "TLS Certificate Types" registry. Used as the {@code type} of
 * {@code NameVariant} and {@code CertChainVariant}.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstCertificateType {

  /** X.509 certificates (RFC 5280). */
  public static final int x509 = 0;

  /** OpenPGP certificates, reserved. */
  public static final int openPGP = 1;

  /** Raw public keys (RFC 7250). */
  public static final int rawPublicKey = 2;

  /** IEEE 1609.2 certificates (RFC 8902). */
  public static final int ieee1609Dot2 = 3;

  /** C509 certificates (draft-ietf-cose-cbor-encoded-cert). */
  public static final int c509 = 4;

  private static final ConstRegistry NAMES = new ConstRegistry("certificate type")
      .put(x509, "X509")
      .put(openPGP, "OpenPGP")
      .put(rawPublicKey, "RawPublicKey")
      .put(ieee1609Dot2, "1609Dot2")
      .put(c509, "C509")
      .withConstants(ConstCertificateType.class);

  private ConstCertificateType() {
  }

  /**
   * Returns {@code "name (code)"} of the code.
   *
   * @param code the code.
   * @return the description.
   */
  public static String describe(int code) {
    return NAMES.describe(code);
  }

  /**
   * Returns the name of the code.
   *
   * @param code the code.
   * @return the name, or {@code "unknown"} if the code is not registered.
   */
  public static String name(int code) {
    return NAMES.nameOf(code);
  }

  /**
   * Resolves a name, alias or decimal code.
   *
   * @param nameOrCode the name, alias or decimal code.
   * @return the code, or {@code null} if the text is not known.
   */
  public static Integer code(String nameOrCode) {
    return NAMES.intCodeOf(nameOrCode);
  }

  /**
   * Registers an additional code and its name.
   *
   * @param code the code.
   * @param name the name.
   * @throws IllegalStateException if the code or the name is already registered.
   */
  public static void register(int code, String name) {
    NAMES.put(code, name);
  }

}
