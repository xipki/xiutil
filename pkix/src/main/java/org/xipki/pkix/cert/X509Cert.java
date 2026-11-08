// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.codec.util.ToStringUtil;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.util.X509Util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * X509 certificate record.
 *
 * @author Lijun Liao (xipki)
 */

public class X509Cert {

  private final Certificate cert;

  private final boolean selfSigned;

  private final X500Name issuer;

  private final BigInteger serialNumber;

  private final X500Name subject;

  private final Instant notBefore;

  private final Instant notAfter;

  private String issuerText;

  private String subjectText;

  private final byte[] subjectKeyId;

  private final byte[] authorityKeyId;

  private final int basicConstraints;

  private final org.xipki.asn1.x509.KeyUsage keyUsage;

  private final byte[] encoded;

  private final int hashCode;

  private final byte[] sha256fp;

  private final GeneralNames san;

  private PublicKey publicKey;

  public X509Cert(Certificate cert) throws CodecException {
    this(cert, null);
  }

  public X509Cert(Certificate cert, byte[] encoded) throws CodecException {
    this.cert = Args.notNull(cert, "certHolder");
    cert.expandDetails();
    this.notBefore = cert.notBefore();
    this.notAfter = cert.notAfter();
    this.serialNumber = cert.serialNumber();

    this.issuer = cert.getIssuer();
    this.subject = cert.getSubject();
    this.selfSigned = subject.equals(issuer);

    Extension extn = getExtension(ExtensionOIDs.subjectAlternativeName);
    this.san = (extn == null) ? null : extn.getSubjectAlternativeName();

    // basic constraints
    extn = getExtension(ExtensionOIDs.basicConstraints);
    if (extn == null) {
      basicConstraints = -1;
    } else {
      BasicConstraints bc = extn.getBasicConstraints();
      if (bc != null && bc.isCA()) {
        Integer bn = bc.pathLenConstraint();
        basicConstraints = bn == null ? Integer.MAX_VALUE : bn;
      } else {
        basicConstraints = -1;
      }
    }

    // keyusage
    extn = getExtension(ExtensionOIDs.keyUsage);
    keyUsage = (extn == null) ? null : extn.getKeyUsage();

    this.encoded = (encoded == null) ? cert.getEncoded() : encoded;
    this.sha256fp = HashAlgo.SHA256.hash(this.encoded);
    this.hashCode = Arrays.hashCode(this.sha256fp);

    // subject key id
    extn = getExtension(ExtensionOIDs.subjectKeyIdentifier);
    subjectKeyId = (extn == null) ? null : extn.getSubjectKeyIdentifier().getKeyIdentifier();

    extn = getExtension(ExtensionOIDs.authorityKeyIdentifier);
    authorityKeyId = (extn == null) ? null : extn.getAuthorityKeyIdentifier()
        .getKeyIdentifierOctets();
  }

  public Certificate getCert() {
    return cert;
  }

  /**
   * Gets the certificate constraints path length from the
   * critical {@code BasicConstraints} extension, (OID = 2.5.29.19).
   * <p>
   * The basic constraints extension identifies whether the subject
   * of the certificate is a Certificate Authority (CA) and
   * how deep a certification path may exist through that CA. The
   * {@code pathLenConstraint} field (see below) is meaningful
   * only if {@code cA} is set to TRUE. In this case, it gives the
   * maximum number of CA certificates that may follow this certificate in a
   * certification path. A value of zero indicates that only an end-entity
   * certificate may follow in the path.
   * <p>
   * The ASN.1 definition for this is:
   * <pre>
   * BasicConstraints ::= SEQUENCE {
   *     cA                  BOOLEAN DEFAULT FALSE,
   *     pathLenConstraint   INTEGER (0..MAX) OPTIONAL }
   * </pre>
   *
   * @return the value of {@code pathLenConstraint} if the
   *     BasicConstraints extension is present in the certificate and the
   *     subject of the certificate is a CA, otherwise -1.
   *     If the subject of the certificate is a CA and
   *     {@code pathLenConstraint} does not appear,
   *     {@code Integer.MAX_VALUE} is returned to indicate that there is no
   *     limit to the allowed length of the certification path.
   */
  public int basicConstraints() {
    return basicConstraints;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public String serialNumberHex() {
    return "0x" + Hex.encode(serialNumber.toByteArray());
  }

  public PublicKey publicKey() {
    if (publicKey == null) {
      try {
        this.publicKey = KeyInfoUtil.getPublicKey(cert.getSubjectPublicKeyInfo());
      } catch (InvalidKeySpecException ex) {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }
    return publicKey;
  }

  public org.xipki.asn1.x509.KeyUsage keyUsage() {
    return keyUsage;
  }

  public GeneralNames subjectAltNames() {
    return san;
  }

  public X500Name issuer() {
    return issuer;
  }

  public X500Name subject() {
    return subject;
  }

  public byte[] subjectKeyId() {
    return subjectKeyId;
  }

  public byte[] authorityKeyId() throws CodecException {
    return authorityKeyId;
  }

  public String subjectText() {
    if (subjectText == null) {
      subjectText = X509Util.x500NameText(subject);
    }
    return subjectText;
  }

  public String issuerText() {
    if (issuerText == null) {
      issuerText = X509Util.x500NameText(subject);
    }
    return issuerText;
  }

  public SubjectPublicKeyInfo subjectPublicKeyInfo() {
    return cert.getSubjectPublicKeyInfo();
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public Instant notBefore() {
    return notBefore;
  }

  public Instant notAfter() {
    return notAfter;
  }

  public byte[] getEncoded() {
    return encoded.clone();
  }

  public String commonName() {
    return X509Util.getCommonName(subject);
  }

  public void verify(PublicKey key) throws SignatureException, InvalidKeyException,
      CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
    if (key instanceof CompositeMLDSAPublicKey) {
      verifyComposite((CompositeMLDSAPublicKey) key);
      return;
    }

    SignAlgo signAlgo = Optional.ofNullable(
        SignAlgo.ofAlgorithmIdentifier(cert.getSignatureAlgorithm()))
        .orElseThrow(() -> new NoSuchAlgorithmException("could not detect SignAlgo"));
    Signature signature = signAlgo.newSignature();
    checkBcSignature(key, signature);
  }

  private void verifyComposite(CompositeMLDSAPublicKey key)
      throws SignatureException, CertificateException,
      NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
    if (!cert.getSignatureAlgorithm().equals(cert.getTBSCertificate().getSignature())) {
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    byte[] m = cert.getTBSCertificate().getEncoded();
    byte[] digestValue = key.suite().ph().hash(m);
    boolean valid = CompositeSigUtil.verifyHash(key, new byte[0], digestValue, cert.signature());
    if (!valid) {
      throw new SignatureException("certificate does not verify with supplied key");
    }
  }

  private void checkBcSignature(PublicKey key, Signature signature)
      throws CertificateException, SignatureException, InvalidKeyException {
    if (!cert.getSignatureAlgorithm().equals(cert.getTBSCertificate().getSignature())) {
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
    }

    signature.initVerify(key);
    signature.update(cert.getTBSCertificate().getEncoded());

    if (!signature.verify(cert.signature())) {
      throw new SignatureException("certificate does not verify with supplied key");
    }
  }

  private Extension getExtension(Asn1Oid extnId) {
    return cert.getTBSCertificate().getExtension(extnId);
  }

  public boolean hasKeyusage(KeyUsage usage) {
    return this.keyUsage.hasFlag(usage.asn1());
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public boolean equals(Object obj) {
    return obj == this || obj instanceof X509Cert
        && Arrays.equals(sha256fp, ((X509Cert) obj).sha256fp);
  }

  @Override
  public String toString() {
    return toString(0);
  }

  public String toString(int level) {
    return toString(cert, level, sha256fp);
  }

  public static String toString(Certificate cert, int level) {
    return toString(cert, level, null);
  }

  public static String toString(Certificate cert, int level, byte[] sha256Fp) {
    StringBuilder sb = new StringBuilder(1000);
    ToStringUtil.appendIndent(sb, level, "Certificate:\n");
    if (sha256Fp != null) {
      ToStringUtil.appendIndent(sb, level + 1, "SHA256 Fingerprint:\n");
      ToStringUtil.appendIndent(sb, level + 2, Hex.encode(sha256Fp)).append("\n");
    }

    cert.toString(sb, level + 1);
    return sb.toString();
  }

  public String toStringSimple() {
    return toStringSimple(0);
  }

  public String toStringSimple(int level) {
    StringBuilder sb = new StringBuilder(1000);
    cert.toStringWithLineSep(sb, level, "Certificate");
    return sb.toString();
  }

}
