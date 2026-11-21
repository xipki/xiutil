// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Catalog;
import org.xipki.c509.registry.ConstExtensionId;

/**
 * Binds the known extension IDs to their value classes.
 *
 * @author Lijun Liao (xipki)
 */
final class C509ExtnCatalog {

  static final C509Catalog<C509ExtnValue> INSTANCE =
      new C509Catalog<C509ExtnValue>(C509RawExtnValue::read, ConstExtensionId::describe)
          .bind(C509SubjectKeyIdentifier.class, C509SubjectKeyIdentifier::read,
              ConstExtensionId.subjectKeyIdentifier)
          .bind(C509KeyUsage.class, C509KeyUsage::read, ConstExtensionId.keyUsage)
          .bind(C509AltName.class, C509AltName::read, ConstExtensionId.subjectAltName,
              ConstExtensionId.issuerAltName)
          .bind(C509BasicConstraints.class, C509BasicConstraints::read,
              ConstExtensionId.basicConstraints)
          .bind(C509CRLDistributionPoints.class, C509CRLDistributionPoints::read,
              ConstExtensionId.cRLDistributionPoints, ConstExtensionId.freshestCRL)
          .bind(C509CertificatePolicies.class, C509CertificatePolicies::read,
              ConstExtensionId.certificatePolicies)
          .bind(C509AuthorityKeyIdentifier.class, C509AuthorityKeyIdentifier::read,
              ConstExtensionId.authorityKeyIdentifier)
          .bind(C509ExtKeyUsageSyntax.class, C509ExtKeyUsageSyntax::read,
              ConstExtensionId.extKeyUsage)
          .bind(C509InfoAccess.class, C509InfoAccess::read,
              ConstExtensionId.authorityInfoAccess, ConstExtensionId.subjectInfoAccess)
          .bind(C509SubjectDirectoryAttributes.class, C509SubjectDirectoryAttributes::read,
              ConstExtensionId.subjectDirectoryAttributes)
          .bind(C509NameConstraints.class, C509NameConstraints::read,
              ConstExtensionId.nameConstraints)
          .bind(C509PolicyMappings.class, C509PolicyMappings::read, ConstExtensionId.policyMappings)
          .bind(C509PolicyConstraints.class, C509PolicyConstraints::read,
              ConstExtensionId.policyConstraints)
          .bind(C509InhibitAnyPolicy.class, C509InhibitAnyPolicy::read,
              ConstExtensionId.inhibitAnyPolicy)
          .bind(C509IPAddrBlocks.class, C509IPAddrBlocks::read,
              ConstExtensionId.ipAddrBlocks, ConstExtensionId.ipAddrBlocks_v2)
          .bindNullable(C509ASIdentifiers.class, C509ASIdentifiers::read,
              C509NullExtnValue.INSTANCE,
              ConstExtensionId.autonomousSysIds, ConstExtensionId.autonomousSysIds_v2)
          .bindAlwaysNull(C509NullExtnValue.INSTANCE, ConstExtensionId.ocsp_nocheck)
          .bindAlwaysNull(C509NullExtnValue.INSTANCE, ConstExtensionId.noRevAvail)
          .bind(C509TLSFeatures.class, C509TLSFeatures::read, ConstExtensionId.tlsfeature)
          .bind(C509ExpiredCertsOnCRL.class, C509ExpiredCertsOnCRL::read,
              ConstExtensionId.expiredCertsOnCRL)
          .bind(C509AcceptableResponseTypes.class, C509AcceptableResponseTypes::read,
              ConstExtensionId.acceptableOcspResponseTypes)
          .bind(C509PreferredSignatureAlgorithms.class, C509PreferredSignatureAlgorithms::read,
              ConstExtensionId.ocsp_pref_sig_algs)
          .bind(C509TNQuery.class, C509TNQuery::read, ConstExtensionId.ocsp_stir_tn)
          .bind(C509AcmeAuthorization.class, C509AcmeAuthorization::read,
              ConstExtensionId.vendor_acmeIdentifier)
      ;

  private C509ExtnCatalog() {
  }

}
