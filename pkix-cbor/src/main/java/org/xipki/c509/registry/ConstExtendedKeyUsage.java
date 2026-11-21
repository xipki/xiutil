// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.id.KeyPurposeOIDs;

import java.util.HashMap;
import java.util.Map;

/**
 * C509 extended key usage identifiers.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstExtendedKeyUsage {

  public static final long anyExtendedKeyUsage = 0;
  public static final long serverAuth = 1;
  public static final long clientAuth = 2;
  public static final long codeSigning = 3;
  public static final long emailProtection = 4;
  public static final long timeStamping = 8;
  public static final long OCSPSigning = 9;
  /** 1.3.6.1.5.2.3.4, Kerberos PKINIT client authentication. */
  public static final long pkinit_KPClientAuth = 10;
  /** 1.3.6.1.5.2.3.5, Kerberos PKINIT KDC. */
  public static final long pkinit_KPKdc = 11;
  /** 1.3.6.1.5.5.7.3.21. */
  public static final long secureShellClient = 12;
  /** 1.3.6.1.5.5.7.3.22. */
  public static final long secureShellServer = 13;
  /** 1.3.6.1.5.5.7.3.35. */
  public static final long bundleSecurity = 14;
  /** 1.3.6.1.5.5.7.3.27. */
  public static final long cmcCA = 15;
  /** 1.3.6.1.5.5.7.3.28. */
  public static final long cmcRA = 16;
  /** 1.3.6.1.5.5.7.3.29. */
  public static final long cmcArchive = 17;
  /** 1.3.6.1.5.5.7.3.32. */
  public static final long cmKGA = 18;
  /** 1.3.6.1.4.1.45605.1, Wi-SUN FAN device. */
  public static final long wisun_fan_device = 20;

  private static final ConstRegistry NAMES = new ConstRegistry("extended key usage")
      .put(anyExtendedKeyUsage, "any")
      .put(serverAuth, "serverAuth")
      .put(clientAuth, "clientAuth")
      .put(codeSigning, "codeSigning")
      .put(emailProtection, "emailProtection")
      .put(timeStamping, "timeStamping")
      .put(OCSPSigning, "OCSPSigning")
      .put(pkinit_KPClientAuth, "pkinitKPClientAuth")
      .put(pkinit_KPKdc, "pkinitKPKDC")
      .put(secureShellClient, "sshClient")
      .put(secureShellServer, "sshServer")
      .put(bundleSecurity, "bundleSecurity")
      .put(cmcCA, "cmcCA")
      .put(cmcRA, "cmcRA")
      .put(cmcArchive, "cmcArchive")
      .put(cmKGA, "cmKGA")
      .put(wisun_fan_device, "wisunFanDevice")
      .withConstants(ConstExtendedKeyUsage.class);

  private static final Map<Long, Asn1Oid> codeToOid = new HashMap<>();

  private static final Map<Asn1Oid, Long> oidToCode = new HashMap<>();

  static {
    oid(anyExtendedKeyUsage, KeyPurposeOIDs.anyExtendedKeyUsage);
    oid(serverAuth,          KeyPurposeOIDs.id_kp_serverAuth);
    oid(clientAuth,          KeyPurposeOIDs.id_kp_clientAuth);
    oid(codeSigning,         KeyPurposeOIDs.id_kp_codeSigning);
    oid(emailProtection,     KeyPurposeOIDs.id_kp_emailProtection);
    oid(timeStamping,        KeyPurposeOIDs.id_kp_timeStamping);
    oid(OCSPSigning,         KeyPurposeOIDs.id_kp_OCSPSigning);
    oid(pkinit_KPClientAuth, KeyPurposeOIDs.id_kp_kerberosClientAuthentication);
    oid(pkinit_KPKdc,        KeyPurposeOIDs.id_kp_kerberosKdc);
    oid(secureShellClient,   KeyPurposeOIDs.id_kp_sshClient);
    oid(secureShellServer,   KeyPurposeOIDs.id_kp_sshServer);
    oid(bundleSecurity,      KeyPurposeOIDs.id_kp_bundleSecurity);
    oid(cmcCA,               KeyPurposeOIDs.id_kp_cmcCA);
    oid(cmcRA,               KeyPurposeOIDs.id_kp_cmcRA);
    oid(cmcArchive,          KeyPurposeOIDs.id_kp_cmcArchive);
    oid(cmKGA,               KeyPurposeOIDs.id_kp_cmKGA);
    oid(wisun_fan_device,    KeyPurposeOIDs.id_kp_wisun_fan_device);
  }

  private ConstExtendedKeyUsage() {
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

  private static void oid(long code, Asn1Oid oid) {
    if (codeToOid.put(code, oid) != null || oidToCode.put(oid, code) != null) {
      throw new IllegalStateException("duplicate extended key usage " + code + " / " + oid.getId());
    }
  }

  /**
   * Returns the OID of the extended key usage code.
   *
   * @param code the C509 extended key usage code.
   * @return the OID, or {@code null} if the code is not registered.
   */
  public static Asn1Oid getOid(long code) {
    return codeToOid.get(code);
  }

  /**
   * Returns the C509 extended key usage code of the OID.
   *
   * @param oid the key purpose OID.
   * @return the code, or {@code null} if the OID has no C509 code.
   */
  public static Long getCode(Asn1Oid oid) {
    return oid == null ? null : oidToCode.get(oid);
  }

  /**
   * Returns the C509 extended key usage code of the OID.
   *
   * @param oid the key purpose OID in dotted-decimal form.
   * @return the code, or {@code null} if the OID has no C509 code.
   */
  public static Long getCode(String oid) {
    return oid == null ? null : oidToCode.get(new Asn1Oid(oid));
  }

}
