// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.codec.Hex;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.ToStringUtil;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.util.C509Util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * X509 certificate record.
 *
 * @author Lijun Liao (xipki)
 */

public class C509Cert {

  private final C509Certificate cert;

  private String issuerText;

  private String subjectText;

  private final byte[] subjectKeyId;

  private final byte[] authorityKeyId;

  private final C509BasicConstraints basicConstraints;

  private final C509KeyUsage keyUsage;

  private final byte[] encoded;

  private final int hashCode;

  private final byte[] sha256fp;

  private final C509AltName san;

  private PublicKey publicKey;

  public C509Cert(C509Certificate cert) throws CodecException {
    this(cert, null);
  }

  public C509Cert(C509Certificate certificate, byte[] encoded) throws CodecException {
    if (certificate != null) {
      this.cert = certificate;
      this.encoded = (encoded == null) ? cert.getEncoded() : encoded;
    } else if (encoded != null) {
      this.encoded = encoded;
      this.cert = C509Certificate.parse(encoded);
    } else {
      throw new IllegalArgumentException("cert and encoded cannot be both null");
    }

    C509Extensions extns = cert.extensions();
    this.san = extns.subjectAltName();

    // basic constraints
    C509BasicConstraints sanValue = extns.basicConstraints();
    this.basicConstraints = (sanValue == null)
        ? C509BasicConstraints.END_ENTITY : sanValue;

    // keyusage
    keyUsage = extns.keyUsage();

    this.sha256fp = HashAlgo.SHA256.hash(this.encoded);
    this.hashCode = Arrays.hashCode(this.sha256fp);

    // subject key id
    subjectKeyId = extns.subjectKeyId();

    // authority key id
    authorityKeyId = extns.authorityKeyId();
  }

  public C509Certificate getCert() {
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
    return basicConstraints.x509Value();
  }

  public BigInteger serialNumber() {
    return cert.serialNumber();
  }

  public String serialNumberHex() {
    return "0x" + Hex.encode(serialNumber().toByteArray());
  }

  public PublicKey publicKey() {
    if (publicKey == null) {
      try {
        this.publicKey = KeyInfoUtil.getPublicKey(cert.body().subjectPublicKey());
      } catch (InvalidKeySpecException ex) {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }
    return publicKey;
  }

  public C509KeyUsage keyUsage() {
    return keyUsage;
  }

  public C509AltName subjectAltNames() {
    return san;
  }

  public C509Name issuer() {
    return cert.issuer();
  }

  public C509Name subject() {
    return cert.subject();
  }

  public byte[] subjectKeyId() {
    return subjectKeyId;
  }

  public byte[] authorityKeyId() {
    return authorityKeyId;
  }

  public String subjectText() {
    if (subjectText == null) {
      subjectText = C509Util.nameText(subject());
    }
    return subjectText;
  }

  public String issuerText() {
    if (issuerText == null) {
      issuerText = C509Util.nameText(issuer());
    }
    return issuerText;
  }

  public C509SubjectPublicKey subjectPublicKeyInfo() {
    return cert.subjectPublicKey();
  }

  public boolean isSelfSigned() {
    return cert.isSelfSigned();
  }

  public Instant notBefore() {
    return cert.notBefore();
  }

  public Instant notAfter() {
    return cert.notAfter();
  }

  public byte[] getEncoded() {
    return encoded.clone();
  }

  public String commonName() {
    return C509Util.getCommonName(subject());
  }

  public void verify(PublicKey key) throws SignatureException, InvalidKeyException,
      NoSuchAlgorithmException, NoSuchProviderException {
    if (key instanceof CompositeMLDSAPublicKey) {
      verifyComposite((CompositeMLDSAPublicKey) key);
      return;
    }

    SignAlgo signAlgo = Optional.ofNullable(
        SignAlgo.ofC509AlgorithmIdentifier(cert.signatureAlgorithm()))
        .orElseThrow(() -> new NoSuchAlgorithmException("could not detect SignAlgo"));
    Signature signature = signAlgo.newSignature();
    checkSignature(cert.signatureAlgorithm(), key, signature);
  }

  private void verifyComposite(CompositeMLDSAPublicKey key)
      throws SignatureException, NoSuchAlgorithmException,
        NoSuchProviderException, InvalidKeyException {
    try {
      byte[] m = cert.body().getEncoded();
      byte[] digestValue = key.suite().ph().hash(m);
      byte[] sigValue = ((BytesSignatureValue) cert.signature()).value();
      boolean valid = CompositeSigUtil.verifyHash(key, new byte[0], digestValue, sigValue);
      if (!valid) {
        throw new SignatureException("certificate does not verify with supplied key");
      }
    } catch (ClassCastException ex) {
      throw new SignatureException(ex);
    }
  }

  private void checkSignature(int algId, PublicKey key, Signature signature)
      throws SignatureException, InvalidKeyException {
    try {
      signature.initVerify(key);
      signature.update(cert.body().getEncoded());

      byte[] sigValue = ((BytesSignatureValue) cert.signature()).value();
      if (ConstSignatureAlgorithm.isEcdsaSignature(algId)) {
        sigValue = Asn1Util.dsaSigPlainToX962(sigValue);
      }
      if (!signature.verify(sigValue)) {
        throw new SignatureException("certificate does not verify with supplied key");
      }
    } catch (ClassCastException ex) {
      throw new SignatureException(ex);
    }
  }

  private C509ExtnValue getExtensionValue(long extnId) {
    C509Extension extn = cert.extensions().get(extnId);
    return extn == null ? null : extn.value();
  }

  public boolean hasKeyusage(KeyUsage usage) {
    return this.keyUsage.hasUsage(usage.c509());
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    return obj instanceof C509Cert
        && Arrays.equals(sha256fp, ((C509Cert) obj).sha256fp);
  }

  @Override
  public String toString() {
    return toString(0);
  }

  public String toString(int level) {
    return toString(cert, level, sha256fp);
  }

  public static String toString(C509Certificate cert, int level) {
    return toString(cert, level, null);
  }

  public static String toString(C509Certificate cert, int level, byte[] sha256Fp) {
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
