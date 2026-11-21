// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * Tags of the GeneralName choice. Negative tags denote well-known otherName types.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstGeneralNameTag {

  public static final int MACAddress = -3;
  public static final int SmtpUTF8Mailbox = -2;
  public static final int hardwareModuleName = -1;
  public static final int otherName = 0;
  public static final int rfc822Name = 1;
  public static final int dNSName = 2;
  public static final int directoryName = 4;
  public static final int uniformResourceIdentifier = 6;
  public static final int iPAddress = 7;
  public static final int registeredID = 8;

  private static final ConstRegistry NAMES = new ConstRegistry("general name")
      .put(MACAddress, "on-MACAddress")
      .put(SmtpUTF8Mailbox, "on-SmtpUTF8Mailbox")
      .put(hardwareModuleName, "on-hardwareModuleName")
      .put(otherName, "otherName")
      .put(rfc822Name, "rfc822Name")
      .put(dNSName, "dNSName")
      .put(directoryName, "directoryName")
      .put(uniformResourceIdentifier, "uri")
      .put(iPAddress, "iPAddress")
      .put(registeredID, "registeredID")
      .withConstants(ConstGeneralNameTag.class);

  private ConstGeneralNameTag() {
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
