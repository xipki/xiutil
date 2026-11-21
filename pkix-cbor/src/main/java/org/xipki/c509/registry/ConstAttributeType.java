// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * C509 attribute types, used in certification requests and in the subject directory attributes
 * extension.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstAttributeType {

  public static final long extensionRequest = 0;
  public static final long challengePassword = 1;
  public static final long privateKeyPossessionStatement = 2;

  // The following codes are provisional and not yet registered.
  public static final long dateOfBirth = 256;
  public static final long placeOfBirth = 257;
  public static final long gender = 258;
  public static final long countryOfCitizenship = 259;
  public static final long countryOfResidence = 260;

  // TBD5 in draft-liao-ace-est-c509, id-cmc-changeSubjectName (1.3.6.1.5.5.7.7.36).
  public static final long changeSubjectName = 261;

  private static final ConstRegistry NAMES = new ConstRegistry("attribute")
      .put(extensionRequest, "ExtensionRequest")
      .put(challengePassword, "ChallengePassword")
      .put(privateKeyPossessionStatement, "PrivateKeyPossessionStatement")
      .put(dateOfBirth, "dateOfBirth")
      .put(placeOfBirth, "placeOfBirth")
      .put(gender, "gender")
      .put(countryOfCitizenship, "countryOfCitizenship")
      .put(countryOfResidence, "countryOfResidence")
      .put(changeSubjectName, "ChangeSubjectName")
      .withConstants(ConstAttributeType.class);

  private ConstAttributeType() {
  }

  /**
   * Returns {@code "name (code)"} of the code.
   *
   * @param code the code.
   * @return the description.
   */
  public static String describe(long code) {
    return NAMES.describe(code);
  }

  /**
   * Returns the name of the code.
   *
   * @param code the code.
   * @return the name, or {@code "unknown"} if the code is not registered.
   */
  public static String name(long code) {
    return NAMES.nameOf(code);
  }

  /**
   * Resolves a name, alias or decimal code.
   *
   * @param nameOrCode the name, alias or decimal code.
   * @return the code, or {@code null} if the text is not known.
   */
  public static Long code(String nameOrCode) {
    return NAMES.codeOf(nameOrCode);
  }

  /**
   * Registers an additional code and its name.
   *
   * @param code the code.
   * @param name the name.
   * @throws IllegalStateException if the code or the name is already registered.
   */
  public static void register(long code, String name) {
    NAMES.put(code, name);
  }

}
