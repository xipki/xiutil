// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.cert;

import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509AuthorityKeyIdentifier;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509SubjectKeyIdentifier;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.TripleState;

import java.math.BigInteger;
import java.security.SignatureException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds natively signed C509 certificates.
 * <pre>
 *   Certificate cert = CertificateBuilder.of(subject, publicKey)
 *       .serialNumber(serial).validity(notBefore, notAfter)
 *       .issuedBy(caCert)
 *       .extension(Extension.critical(ExtnId.KEY_USAGE, KeyUsage.of(KeyUsage.CRL_SIGN)))
 *       .build(signer);
 * </pre>
 * The extensions are sorted by ID. The authority key identifier and the issuer alternative
 * name are derived from the issuer certificate and may not be added explicitly.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificateBuilder {

  private final C509Name subject;

  private final C509SubjectPublicKey publicKey;

  private final Map<Long, C509Extension> extensions = new LinkedHashMap<>();

  private BigInteger serialNumber = BigInteger.ONE;

  private Instant notBefore = Instant.now();

  private Instant notAfter;

  private C509Certificate issuer;

  private C509AkiMode akiMode = C509AkiMode.KEY_ID;

  private TripleState issuerAltName = TripleState.forbidden;

  private boolean autoSubjectKeyId;

  private C509CertificateBuilder(C509Name subject, C509SubjectPublicKey publicKey) {
    this.subject = Args.notNull(subject, "subject");
    this.publicKey = Args.notNull(publicKey, "publicKey");
  }

  public static C509CertificateBuilder of(C509Name subject, C509SubjectPublicKey publicKey) {
    return new C509CertificateBuilder(subject, publicKey);
  }

  public C509CertificateBuilder serialNumber(BigInteger serialNumber) {
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    return this;
  }

  /**
   * @param notAfter the end of validity, null for no expiry.
   */
  public C509CertificateBuilder validity(Instant notBefore, Instant notAfter) {
    this.notBefore = Args.notNull(notBefore, "notBefore");
    this.notAfter = notAfter;
    return this;
  }

  /**
   * Sets the issuer certificate; without it the certificate is self-signed.
   */
  public C509CertificateBuilder issuedBy(C509Certificate issuer) {
    this.issuer = issuer;
    return this;
  }

  public C509CertificateBuilder akiMode(C509AkiMode akiMode) {
    this.akiMode = Args.notNull(akiMode, "akiMode");
    return this;
  }

  /**
   * Whether to copy the subject alternative name of the issuer as issuer alternative name.
   */
  public C509CertificateBuilder issuerAltName(TripleState mode) {
    this.issuerAltName = Args.notNull(mode, "mode");
    return this;
  }

  /**
   * Whether to derive the subject key identifier from the public key if none is given.
   */
  public C509CertificateBuilder autoSubjectKeyId(boolean enabled) {
    this.autoSubjectKeyId = enabled;
    return this;
  }

  public C509CertificateBuilder extension(C509Extension extension) {
    long id = extension.id();
    if (id == ConstExtensionId.authorityKeyIdentifier || id == ConstExtensionId.issuerAltName) {
      throw new IllegalArgumentException(ConstExtensionId.name(id)
          + " shall be derived from the issuer certificate");
    }

    if (extensions.putIfAbsent(id, extension) != null) {
      throw new IllegalArgumentException(
          "duplicate extension " + ConstExtensionId.describe(id));
    }
    return this;
  }

  public C509CertificateBuilder extension(long id, boolean critical, C509ExtnValue value) {
    return extension(new C509Extension(id, critical, value));
  }

  public C509CertificateBuilder removeExtension(long id) {
    extensions.remove(id);
    return this;
  }

  public C509Certificate build(AtomicContentSigner signer) throws CodecException, SignatureException {
    C509TBSCertificate body = body(signer.c509Algorithm());
    return new C509Certificate(body, signer.atomicC509Sign(body.getEncoded()));
  }

  public C509TBSCertificate body(int signatureAlgorithm) throws CodecException {
    Map<Long, C509Extension> all = new LinkedHashMap<>(extensions);
    if (issuer != null) {
      C509Extension aki = authorityKeyId();
      if (aki != null) {
        all.put(aki.id(), aki);
      }
    }

    if (issuerAltName != TripleState.forbidden) {
      C509AltName san = issuer == null ? null : issuer.extension(ConstExtensionId.subjectAltName,
          C509AltName.class);
      if (san != null) {
        all.put(ConstExtensionId.issuerAltName,
            C509Extension.nonCritical(ConstExtensionId.issuerAltName, san));
      } else if (issuerAltName == TripleState.required) {
        throw new CodecException("the issuer certificate has no subject alternative name");
      }
    }

    if (autoSubjectKeyId && !all.containsKey(ConstExtensionId.subjectKeyIdentifier)) {
      all.put(ConstExtensionId.subjectKeyIdentifier, C509Extension.nonCritical(
          ConstExtensionId.subjectKeyIdentifier,
          new C509SubjectKeyIdentifier(publicKey.computeSubjectKeyIdentifier())));
    }

    return new C509TBSCertificate(C509TBSCertificate.TYPE_NATIVE, serialNumber,
        signatureAlgorithm,
        issuer == null ? null : issuer.subject(), subject, notBefore, notAfter, publicKey,
        C509Extensions.sorted(all.values()));
  }

  private C509Extension authorityKeyId() {
    if (akiMode == C509AkiMode.NONE) {
      return null;
    }

    byte[] keyId = null;
    if (akiMode != C509AkiMode.ISSUER_AND_SERIAL) {
      keyId = issuer.extensions().subjectKeyId();
      if (keyId == null) {
        throw new IllegalStateException("the issuer certificate has no subject key identifier");
      }
    }

    C509AuthorityKeyIdentifier value = (akiMode == C509AkiMode.KEY_ID)
        ? C509AuthorityKeyIdentifier.ofKeyId(keyId)
        : C509AuthorityKeyIdentifier.ofIssuerAndSerial(keyId,
            C509GeneralNames.of(C509GeneralName.directory(issuer.subject())),
                issuer.serialNumber());
    return C509Extension.nonCritical(ConstExtensionId.authorityKeyIdentifier, value);
  }

}
