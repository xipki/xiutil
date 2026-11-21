// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * Access methods of the authority / subject information access extensions.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstAccessMethod {

  /** 1.3.6.1.5.5.7.48.1. */
  public static final int ocsp = 1;
  /** 1.3.6.1.5.5.7.48.2. */
  public static final int caIssuers = 2;
  /** 1.3.6.1.5.5.7.48.3. */
  public static final int timeStamping = 3;
  /** 1.3.6.1.5.5.7.48.5. */
  public static final int caRepository = 5;
  public static final int rpkiManifest = 10;
  public static final int signedObject = 11;
  public static final int rpkiNotify = 13;

  private static final ConstRegistry NAMES = new ConstRegistry("access method")
      .put(ocsp, "ocsp", "pkix-ocsp")
      .put(caIssuers, "caIssuers")
      .put(timeStamping, "timeStamping")
      .put(caRepository, "caRepository")
      .put(rpkiManifest, "rpkiManifest")
      .put(signedObject, "signedObject")
      .put(rpkiNotify, "rpkiNotify")
      .withConstants(ConstAccessMethod.class);

  private ConstAccessMethod() {
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
