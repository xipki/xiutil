// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * C509 certificate policy identifiers.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstCertificatePolicy {

  public static final long anyPolicy = 0;
  public static final long domain_validated = 1;
  public static final long organization_validated = 2;
  public static final long individual_validated = 3;
  public static final long ev_guidelines = 4;
  /** 1.3.6.1.5.5.7.14.2, Resource PKI. */
  public static final long ipAddr_asNumber = 7;
  /** 1.3.6.1.5.5.7.14.3, Resource PKI (alternative). */
  public static final long ipAddr_asNumber_v2 = 8;
  /** 2.23.146.1.2.1.0, remote SIM provisioning: certificate issuer. */
  public static final long rspRole_ci = 24;
  public static final long rspRole_euicc_v2 = 25;
  public static final long rspRole_euicc = 26;
  public static final long rspRole_eum_v2 = 27;
  public static final long rspRole_eum = 28;
  public static final long rspRole_dp_tls_v2 = 29;
  public static final long rspRole_dp_tls = 30;
  public static final long rspRole_dp_auth_v2 = 31;
  public static final long rspRole_dp_auth = 32;
  public static final long rspRole_dp_pb_v2 = 33;
  public static final long rspRole_dp_pb = 34;
  public static final long rspRole_ds_tls_v2 = 35;
  public static final long rspRole_ds_tls = 36;
  public static final long rspRole_ds_auth_v2 = 37;
  public static final long rspRole_ds_auth = 38;

  private static final ConstRegistry NAMES = new ConstRegistry("certificate policy")
      .put(anyPolicy, "anyPolicy")
      .put(domain_validated, "domain-validated")
      .put(organization_validated, "organization-validated")
      .put(individual_validated, "individual-validated")
      .put(ev_guidelines, "ev-guidelines")
      .put(ipAddr_asNumber, "rpki-ipAddr-asNumber")
      .put(ipAddr_asNumber_v2, "rpki-ipAddr-asNumber-v2")
      .put(rspRole_ci, "rspRole-ci")
      .put(rspRole_euicc_v2, "rspRole-euicc-v2")
      .put(rspRole_euicc, "rspRole-euicc")
      .put(rspRole_eum_v2, "rspRole-eum-v2")
      .put(rspRole_eum, "rspRole-eum")
      .put(rspRole_dp_tls_v2, "rspRole-dp-tls-v2")
      .put(rspRole_dp_tls, "rspRole-dp-tls")
      .put(rspRole_dp_auth_v2, "rspRole-dp-auth-v2")
      .put(rspRole_dp_auth, "rspRole-dp-auth")
      .put(rspRole_dp_pb_v2, "rspRole-dp-pb-v2")
      .put(rspRole_dp_pb, "rspRole-dp-pb")
      .put(rspRole_ds_tls_v2, "rspRole-ds-tls-v2")
      .put(rspRole_ds_tls, "rspRole-ds-tls")
      .put(rspRole_ds_auth_v2, "rspRole-ds-auth-v2")
      .put(rspRole_ds_auth, "rspRole-ds-auth")
      .withConstants(ConstCertificatePolicy.class);

  private ConstCertificatePolicy() {
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
