// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.asn1.x509.KeyUsage;
import org.xipki.asn1.x509.TBSCertificate;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * JCE X509 Certificate.
 *
 * @author Lijun Liao (xipki)
 */
public class JceX509Certificate extends X509Certificate {

  private final Certificate cert;

  private final byte[] encoded;

  private final PublicKey publicKey;

  private final X500Principal issuer;

  private final X500Principal subject;

  private final int version;

  private final int basicConstraints;

  private final boolean[] keyUsage;

  private final Set<String> criticalExtensionOIDs;

  private final Set<String> nonCriticalExtensionOIDs;

  public JceX509Certificate(Certificate cert) throws CertificateEncodingException {
    this.cert = Args.notNull(cert, "cert");
    try {
      TBSCertificate tbs = cert.getTBSCertificate();
      this.version = tbs.version();
      this.encoded = cert.getEncoded();
      this.issuer = new X500Principal(tbs.getIssuer().getEncoded());
      this.subject = new X500Principal(tbs.getSubject().getEncoded());

      Extensions extns = tbs.getExtensions();
      this.criticalExtensionOIDs = toTextIdSet(extns.getCriticalExtensionIds());
      this.nonCriticalExtensionOIDs = toTextIdSet(extns.getNonCriticalExtensionIds());
      this.publicKey = KeyInfoUtil.getPublicKey(cert.getTBSCertificate().getSubjectPublicKeyInfo());
      // basic constraints
      Extension extn = extns.getExtension(ExtensionOIDs.basicConstraints);
      if (extn == null) {
        this.basicConstraints = -1;
      } else {
        BasicConstraints bc = extn.getBasicConstraints();
        if (bc.isCA()) {
          Integer bn = bc.pathLenConstraint();
          this.basicConstraints = bn == null ? Integer.MAX_VALUE : bn;
        } else {
          this.basicConstraints = -1;
        }
      }

      // key usage
      extn = extns.getExtension(ExtensionOIDs.keyUsage);
      if (extn == null) {
        keyUsage = null;
      } else {
        KeyUsage d = extn.getKeyUsage();
        boolean[] booleans = d.toBooleans();
        keyUsage = booleans.length < 9 ? Arrays.copyOf(booleans, 9) : booleans;
      }
    } catch (InvalidKeySpecException e) {
      throw new CertificateEncodingException(e);
    }
  }

  private static Set<String> toTextIdSet(Set<Asn1Oid> oids) {
    Set<String> set = new HashSet<>();
    if (oids != null) {
      for (Asn1Oid oid : oids) {
        set.add(oid.getId());
      }
    }
    return Collections.unmodifiableSet(set);
  }

  @Override
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    checkValidity(new Date());
  }

  @Override
  public void checkValidity(Date date)
      throws CertificateExpiredException, CertificateNotYetValidException {
    if (date == null) {
      date = new Date();
    }

    if (date.after(getNotAfter())) {
      throw new CertificateExpiredException();
    }

    if (date.before(getNotBefore())) {
      throw new CertificateNotYetValidException();
    }
  }

  @Override
  public int getVersion() {
    return version;
  }

  @Override
  public BigInteger getSerialNumber() {
    return cert.getTBSCertificate().serialNumber();
  }

  @Override
  public Principal getIssuerDN() {
    return issuer;
  }

  @Override
  public Principal getSubjectDN() {
    return subject;
  }

  @Override
  public Date getNotBefore() {
    return Date.from(cert.notBefore());
  }

  @Override
  public Date getNotAfter() {
    return Date.from(cert.notAfter());
  }

  @Override
  public byte[] getTBSCertificate() throws CertificateEncodingException {
    return cert.getTBSCertificate().getEncoded();
  }

  @Override
  public byte[] getSignature() {
    return cert.signature();
  }

  @Override
  public String getSigAlgName() {
    try {
      return SignAlgo.ofAlgorithmIdentifier(cert.getSignatureAlgorithm()).jceName();
    } catch (NoSuchAlgorithmException e) {
      return "";
    }
  }

  @Override
  public String getSigAlgOID() {
    return cert.getTBSCertificate().getSignature().getAlgorithm().getId();
  }

  @Override
  public byte[] getSigAlgParams() {
    Asn1Encodable asn1 = cert.getTBSCertificate().getSignature().getParameters();
    return asn1 == null ? null : asn1.getEncoded();
  }

  @Override
  public boolean[] getIssuerUniqueID() {
    return null;
  }

  @Override
  public boolean[] getSubjectUniqueID() {
    return null;
  }

  @Override
  public boolean[] getKeyUsage() {
    return keyUsage == null ? null : keyUsage.clone();
  }

  @Override
  public int getBasicConstraints() {
    return basicConstraints;
  }

  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    return encoded.clone();
  }

  @Override
  public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
      InvalidKeyException, NoSuchProviderException, SignatureException {
    verify(key, (Provider) null);
  }

  @Override
  public void verify(PublicKey key, String sigProvider) throws CertificateException,
      NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    Provider provider = Security.getProvider(sigProvider);
    verify(publicKey, provider);
  }

  @Override
  public String toString() {
    return cert.toString();
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean hasUnsupportedCriticalExtension() {
    return false;
  }

  @Override
  public Set<String> getCriticalExtensionOIDs() {
    return criticalExtensionOIDs;
  }

  @Override
  public Set<String> getNonCriticalExtensionOIDs() {
    return nonCriticalExtensionOIDs;
  }

  @Override
  public byte[] getExtensionValue(String oid) {
    Extensions extensions = cert.getTBSCertificate().getExtensions();
    Extension extn = extensions.getExtension(new Asn1Oid(oid));
    if (extn == null) {
      return null;
    }

    return extn.getExtnValue().getEncoded();
  }

  @Override
  public X500Principal getIssuerX500Principal() {
    return issuer;
  }

  @Override
  public X500Principal getSubjectX500Principal() {
    return subject;
  }

}
