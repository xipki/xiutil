// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

/**
 * C509 extension identifiers.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstExtensionId {

  public static final long subjectKeyIdentifier = 1;
  public static final long keyUsage = 2;
  public static final long subjectAltName = 3;
  public static final long basicConstraints = 4;
  public static final long cRLDistributionPoints = 5;
  public static final long certificatePolicies = 6;
  public static final long authorityKeyIdentifier = 7;
  public static final long extKeyUsage = 8;
  public static final long authorityInfoAccess = 9;
  public static final long subjectDirectoryAttributes = 24;
  public static final long issuerAltName = 25;
  public static final long nameConstraints = 26;
  public static final long policyMappings = 27;
  public static final long policyConstraints = 28;
  public static final long freshestCRL = 29;
  public static final long inhibitAnyPolicy = 30;
  public static final long subjectInfoAccess = 31;
  public static final long ipAddrBlocks = 32;
  public static final long autonomousSysIds = 33;
  public static final long ipAddrBlocks_v2 = 34;
  public static final long autonomousSysIds_v2 = 35;
  public static final long ocsp_nocheck = 36;
  public static final long tlsfeature = 38;
  public static final long noRevAvail = 39;

  /** CRL extension. */
  public static final long expiredCertsOnCRL = 128;

  /** OCSP extension. */
  public static final long acceptableOcspResponseTypes = 129;

  /** OCSP extension. */
  public static final long ocsp_pref_sig_algs = 130;

  /**
   * OCSP single request extension TN Query (draft-ietf-stir-certificates-ocsp), TBD4 in
   * draft-liao-cose-c509-revocation-01.
   */
  public static final long ocsp_stir_tn = 131;

  // RFC 8737: id-pe-acmeIdentifier = "1.3.6.1.5.5.7.1.31";
  public static final long vendor_acmeIdentifier = 65535;

  private static final ConstRegistry NAMES = new ConstRegistry("extension")
      .put(subjectKeyIdentifier, "SubjectKeyIdentifier")
      .put(keyUsage, "KeyUsage")
      .put(subjectAltName, "SubjectAlternativeName", "SubjectAltName")
      .put(basicConstraints, "BasicConstraints")
      .put(cRLDistributionPoints, "CRLDistributionPoints", "CRLDPs")
      .put(certificatePolicies, "CertificatePolicies")
      .put(authorityKeyIdentifier, "AuthorityKeyIdentifier")
      .put(extKeyUsage, "ExtendedKeyUsage", "ExtKeyUsage")
      .put(authorityInfoAccess, "AuthorityInfoAccess")
      .put(subjectDirectoryAttributes, "SubjectDirectoryAttributes")
      .put(issuerAltName, "IssuerAlternativeName", "IssuerAltName")
      .put(nameConstraints, "NameConstraints")
      .put(policyMappings, "PolicyMappings")
      .put(policyConstraints, "PolicyConstraints")
      .put(freshestCRL, "FreshestCRL")
      .put(inhibitAnyPolicy, "InhibitAnyPolicy")
      .put(subjectInfoAccess, "SubjectInfoAccess")
      .put(ipAddrBlocks, "IPAddrBlocks")
      .put(autonomousSysIds, "ASIdentifiers")
      .put(ipAddrBlocks_v2, "IPAddrBlocksV2")
      .put(autonomousSysIds_v2, "ASIdentifiersV2")
      .put(ocsp_nocheck, "OCSPNoCheck")
      .put(tlsfeature, "TLSFeatures", "TLSFeature")
      .put(noRevAvail, "noRevAvail")
      .put(expiredCertsOnCRL, "ExpiredCertsOnCRL")
      .put(acceptableOcspResponseTypes, "AcceptableOCSPResponseTypes")
      .put(ocsp_pref_sig_algs, "PreferredSignatureAlgorithms")
      .put(ocsp_stir_tn, "TNQuery")
      .put(vendor_acmeIdentifier, "acmeIdentifier")

      .withConstants(ConstExtensionId.class);

  private ConstExtensionId() {
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
