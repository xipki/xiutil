// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.crl;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.util.Args;

import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds full and delta C509 CRLs.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CRLBuilder {

  private final long crlNumber;

  private final C509Certificate authority;

  private final Instant thisUpdate;

  private final Instant nextUpdate;

  private Long baseCrlNumber;

  private final Map<Long, C509Extension> extensions = new LinkedHashMap<>();

  private final List<C509PerIssuerRevokedCertsBuilder> groups = new ArrayList<>();

  /**
   * @param authority the CRL issuer; must have the key usage cRLSign and a subject key
   *                  identifier.
   */
  public C509CRLBuilder(
      long crlNumber, C509Certificate authority, Instant thisUpdate, Instant nextUpdate) {
    if (crlNumber <= 0) {
      throw new IllegalArgumentException("crlNumber must be positive");
    }
    this.crlNumber = crlNumber;
    this.authority = Args.notNull(authority, "authority");
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = nextUpdate;
    if (!authority.extensions().hasKeyUsage(C509KeyUsage.CRL_SIGN)) {
      throw new IllegalArgumentException("the authority certificate lacks key usage cRLSign");
    }
    // the CRL field authorityKeyIdentifier is mandatory
    if (authority.extensions().subjectKeyId() == null) {
      throw new IllegalArgumentException(
          "the authority certificate lacks the subject key identifier extension");
    }
  }

  /**
   * Makes this a delta CRL to the given base CRL.
   */
  public C509CRLBuilder deltaOf(long baseCrlNumber) {
    if (!groups.isEmpty()) {
      throw new IllegalStateException("deltaOf() must be called before group()");
    }
    this.baseCrlNumber = baseCrlNumber;
    return this;
  }

  public C509CRLBuilder extension(long id, boolean critical, C509ExtnValue value) {
    C509Extension e = new C509Extension(id, critical, value);
    if (extensions.putIfAbsent(id, e) != null) {
      throw new IllegalArgumentException("duplicate extension " + ConstExtensionId.describe(id));
    }
    return this;
  }

  /**
   * Returns the group for certificates issued by the CRL issuer itself.
   */
  public C509PerIssuerRevokedCertsBuilder group(
      boolean sorted, boolean withDates, boolean withReasons) {
    return group(authoritySubject(), sorted, withDates, withReasons);
  }

  private C509NameVariant authoritySubject() {
    return C509NameVariant.ofC509(authority.subject());
  }

  /**
   * Returns the group for certificates of the given issuer (indirect CRL). Asking twice for
   * the same issuer returns the same group, provided the options are equal.
   */
  public C509PerIssuerRevokedCertsBuilder group(
      C509Name issuer, boolean sorted, boolean withDates, boolean withReasons) {
    return group(C509NameVariant.ofC509(issuer), sorted, withDates, withReasons);
  }

  /**
   * Returns the group for certificates of the given issuer (indirect CRL). Asking twice for
   * the same issuer returns the same group, provided the options are equal.
   */
  public C509PerIssuerRevokedCertsBuilder group(
      C509NameVariant issuer, boolean sorted, boolean withDates, boolean withReasons) {
    C509NameVariant key = issuer.equals(authoritySubject()) ? null : issuer;
    for (C509PerIssuerRevokedCertsBuilder g : groups) {
      if (Objects.equals(key, g.issuer())) {
        if (!g.hasOptions(sorted, withDates, withReasons)) {
          throw new IllegalArgumentException("the group of " + issuer
              + " exists with other options: " + g.options());
        }
        return g;
      }
    }
    C509PerIssuerRevokedCertsBuilder g = new C509PerIssuerRevokedCertsBuilder(
        key, baseCrlNumber != null, sorted, withDates, withReasons);
    groups.add(g);
    return g;
  }

  public C509TBSCertList body(int signatureAlgorithm) {
    C509CRLInfoData header = new C509CRLInfoData(signatureAlgorithm, authoritySubject(),
        authority.extensions().subjectKeyId(), crlNumber, thisUpdate, nextUpdate,
        baseCrlNumber, new C509Extensions(extensions.values()));
    long thisUpdateEpoch = header.thisUpdate().getEpochSecond();
    List<C509PerIssuerRevokedCerts> list = new ArrayList<>(groups.size());
    for (C509PerIssuerRevokedCertsBuilder g : groups) {
      list.add(g.build(thisUpdateEpoch));
    }
    return new C509TBSCertList(header, list);
  }

  public C509CertificateList build(AtomicContentSigner signer) throws SignatureException {
    C509TBSCertList body = body(signer.c509Algorithm());
    return new C509CertificateList(body, signer.atomicC509Sign(body.getEncoded()));
  }

}
