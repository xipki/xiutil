// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * Policy qualifier identifiers.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstPolicyQualifier {

  public static final int cps = 1;
  public static final int unotice = 2;

  private static final ConstRegistry NAMES = new ConstRegistry("policy qualifier")
      .put(cps, "cps")
      .put(unotice, "unotice", "userNotice")
      .withConstants(ConstPolicyQualifier.class);

  private ConstPolicyQualifier() {
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
