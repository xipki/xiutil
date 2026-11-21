// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * C509 private key types, see the "C509 Private Key Types" registry.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstPrivateKeyType {

  /** Asymmetric Key Package (RFC 5958): the PrivateKey OCTET STRING value as byte string. */
  public static final int asymmetricKeyPackage = 0;

  /** COSE Key Object (RFC 9052): a COSE_Key containing a private key. */
  public static final int coseKey = 1;

  private static final ConstRegistry NAMES = new ConstRegistry("private key type")
      .put(asymmetricKeyPackage, "AsymmetricKeyPackage")
      .put(coseKey, "COSE_Key")
      .withConstants(ConstPrivateKeyType.class);

  private ConstPrivateKeyType() {
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
