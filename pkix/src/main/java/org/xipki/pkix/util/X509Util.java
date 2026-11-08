// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.asn1.spdm.DmtfDeviceInfo;
import org.xipki.asn1.x500.AttributeTypeAndValue;
import org.xipki.asn1.x500.RDN;
import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.asn1.x509.*;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.util.misc.PemEncoder;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.cert.X509Crl;
import org.xipki.codec.ConfPairs;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.codec.util.IoUtil;
import org.xipki.util.exception.PkixException;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.misc.CollectionUtil;
import org.xipki.util.misc.CompareUtil;
import org.xipki.util.misc.LogUtil;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.xipki.codec.util.Args.notNull;

/**
 * X509 Util.
 *
 * @author Lijun Liao (xipki)
 */
public class X509Util {

  private static final Logger LOG = LoggerFactory.getLogger(X509Util.class);

  private static final byte[] BEGIN_PEM = StringUtil.toUtf8Bytes("-----BEGIN");

  private static final byte[] END_PEM = StringUtil.toUtf8Bytes("-----END");

  private static final byte[] PEM_SEP = StringUtil.toUtf8Bytes("-----");

  private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";

  private static final String END_CERTIFICATE   = "-----END CERTIFICATE-----";

  private X509Util() {
  }

  public static String getCommonName(X500Name name) {
    List<RDN> rdns = notNull(name, "name").getRDNs(AttributeOIDs.commonName);
    if (rdns != null && !rdns.isEmpty()) {
      RDN rdn = rdns.get(0);
      AttributeTypeAndValue atv = null;
      if (rdn.isMultiValued()) {
        for (AttributeTypeAndValue m : rdn) {
          if (m.getType().equals(AttributeOIDs.commonName)) {
            atv = m;
            break;
          }
        }
      } else {
        atv = rdn.getFirst();
      }
      return (atv == null) ? null : rdnValueToString(atv.getValue());
    }
    return null;
  } // method getCommonName

  public static X500Name reverse(X500Name name) {
    List<RDN> orig = notNull(name, "name").getRDNs();
    final int n = orig.size();
    RDN[] newRdn = new RDN[n];
    for (int i = 0; i < n; i++) {
      newRdn[i] = orig.get(n - 1 - i);
    }
    return new X500Name(newRdn);
  }

  public static X509Cert parseCert(File file) throws IOException, CertificateException {
    return parseCert(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static List<X509Cert> parseCerts(byte[] certsBytes)
      throws IOException, CertificateException {
    try (InputStream is = new ByteArrayInputStream(certsBytes)) {
      return parseCerts(is);
    }
  }

  public static List<X509Cert> parseCerts(File certsFile) throws IOException, CertificateException {
    try (InputStream is = Files.newInputStream(certsFile.toPath())) {
      return parseCerts(is);
    }
  }

  /**
   * Read a list of X.509 certificates from the input stream consisting of
   * several PEM certificates.
   * The specified stream remains open after this method returns.
   * @param certsStream the input stream of PEM certificates.
   * @return a list of X.509 certificates.
   * @throws IOException if IO error occurs while reading the input stream.
   * @throws CertificateException if error occurs parsing the certificates.
   */
  private static List<X509Cert> parseCerts(InputStream certsStream)
      throws IOException, CertificateException {
    List<X509Cert> certs = new LinkedList<>();
    try (PemReader pemReader = new PemReader(
        new InputStreamReader(certsStream, StandardCharsets.UTF_8))) {
      PemObject pemObj;
      while ((pemObj = pemReader.readPemObject()) != null) {
        if ("CERTIFICATE".equalsIgnoreCase(pemObj.getType())) {
          certs.add(parseCert(pemObj.getContent()));
        }
      }
    }
    return certs;
  }

  public static X509Cert parseCert(byte[] bytes) throws CertificateEncodingException {
    byte[] certBytes = null;
    if (CompareUtil.areEqual(notNull(bytes, "bytes"), 0, BEGIN_PEM, 0, BEGIN_PEM.length)) {
      try (PemReader r = new PemReader(new InputStreamReader(
          new ByteArrayInputStream(bytes), StandardCharsets.UTF_8))) {
        PemObject obj;
        while (true) {
          obj = r.readPemObject();
          if (obj == null) {
            break;
          }

          if (obj.getType().equalsIgnoreCase("CERTIFICATE")) {
            certBytes = obj.getContent();
            break;
          }
        }

        if (certBytes == null) {
          throw new CertificateEncodingException("found no certificate");
        }
      } catch (IOException ex) {
        throw new CertificateEncodingException("error while parsing bytes");
      }
    } else {
      certBytes = bytes;
    }

    try {
      byte[] derBytes = toDerEncoded(certBytes);
      return new X509Cert(Certificate.fromEncoded(derBytes), derBytes);
    } catch (CodecException ex) {
      throw new CertificateEncodingException("error decoding certificate: " + ex.getMessage(), ex);
    }
  }

  public static CertificationRequest parseCsr(File file) throws IOException {
    return parseCsr(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static CertificationRequest parseCsr(byte[] csrBytes) throws IOException {
    try {
      return CertificationRequest.fromEncoded(toDerEncoded(notNull(csrBytes, "csrBytes")));
    } catch (CodecException ex) {
      throw new IOException("invalid CSR bytes", ex);
    }
  }

  public static byte[] toDerEncoded(byte[] bytes) {
    Args.notNull(bytes, "bytes");
    final int len = bytes.length;

    if (len > 23) {
      // check if PEM encoded
      if (CompareUtil.areEqual(bytes, 0, BEGIN_PEM, 0, BEGIN_PEM.length)) {
        int base64Start = -1;
        int base64End = -1;

        for (int i = BEGIN_PEM.length + 1; i < len; i++) {
          if (CompareUtil.areEqual(bytes, i, PEM_SEP, 0, PEM_SEP.length)) {
            base64Start = i + PEM_SEP.length;
            break;
          }
        }

        if (bytes[base64Start] == '\n') {
          base64Start++;
        }

        for (int i = len - END_PEM.length - 6; i > 0; i--) {
          if (CompareUtil.areEqual(bytes, i, END_PEM, 0, END_PEM.length)) {
            base64End = i - 1;
            break;
          }
        }

        if (bytes[base64End - 1] == '\r') {
          base64End--;
        }

        byte[] base64Bytes = new byte[base64End - base64Start + 1];
        System.arraycopy(bytes, base64Start, base64Bytes, 0, base64Bytes.length);
        return Base64.decode(base64Bytes);
      }
    }

    // check whether base64 encoded
    if (Base64.getEncoder().containsOnlyValidChars(bytes, 0, 10)) {
      return Base64.decode(bytes);
    }

    return bytes;
  } // method toDerEncoded

  public static String toPemCert(X509Cert cert) {
    return StringUtil.toUtf8String(PemEncoder.encode(
        notNull(cert, "cert").getEncoded(), PemEncoder.PemLabel.CERTIFICATE));
  }

  public static X509Crl parseCrl(File file) throws IOException, CRLException {
    return parseCrl(Files.readAllBytes(IoUtil.expandFilepath(notNull(file, "file")).toPath()));
  }

  public static X509Crl parseCrl(byte[] encodedCrl) throws CRLException {
    try {
      byte[] encoded = toDerEncoded(notNull(encodedCrl, "encodedCrl"));
      return new X509Crl(CertificateList.fromEncoded(encoded), encoded);
    } catch (CodecException ex) {
      throw new CRLException("the given one is not a valid X.509 CRL");
    }
  }

  public static String x500NameText(X500Name name) {
    StringBuilder buf = new StringBuilder(20);
    notNull(name, "name").toString(buf, 0);
    return buf.toString();
  }

  public static long fpCanonicalizedName(X500Name name) {
    return FpIdCalculator.hash(StringUtil.toUtf8Bytes(canonicalizeName(notNull(name, "name"))));
  }

  public static String canonicalizeName(X500Name name) {
    Set<Asn1Oid> tmpTypes = notNull(name, "name").getAttributeTypes();
    int len = tmpTypes.size();
    List<String> types = new ArrayList<>(len);
    for (Asn1Oid type : tmpTypes) {
      types.add(type.getId());
    }

    Collections.sort(types);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      String type = types.get(i);
      if (i > 0) {
        sb.append(",");
      }
      sb.append(type).append("=");
      List<RDN> rdns = name.getRDNs(new Asn1Oid(type));

      List<String> values = new ArrayList<>(1);
      for (RDN rdn : rdns) {
        if (rdn.isMultiValued()) {
          for (AttributeTypeAndValue atv : rdn) {
            if (type.equals(atv.getType().getId())) {
              values.add(valueToString(atv.getValue()).toLowerCase());
            }
          }
        } else {
          values.add(valueToString(rdn.getFirst().getValue()).toLowerCase());
        }
      } // end for(j)

      sb.append(values.get(0));

      final int n2 = values.size();
      if (n2 > 1) {
        for (int j = 1; j < n2; j++) {
          sb.append(";").append(values.get(j));
        }
      }
    } // end for(i)

    return sb.toString();
  } // method canonicalizeName

  public static String rdnValueToString(Asn1Encodable value) {
    Args.notNull(value, "value");
    if (value instanceof AbstractAsn1String) { // && !(value instanceof DERUniversalString)) {
      return ((AbstractAsn1String) value).getString();
    } else {
      return "#" + Hex.encode(value.getEncoded());
    }
  }

  public static org.xipki.asn1.x509.KeyUsage createKeyUsage(Set<KeyUsage> usages) {
    Args.notEmpty(usages, "usages");

    org.xipki.asn1.x509.KeyUsage[] singleUsages =
        new org.xipki.asn1.x509.KeyUsage[usages.size()];
    int i = 0;
    for (KeyUsage keyUsage : usages) {
      singleUsages[i++] = keyUsage.asn1();
    }

    return new org.xipki.asn1.x509.KeyUsage(singleUsages);
  }

  public static ExtendedKeyUsage createExtendedUsage(Collection<Asn1Oid> usages) {
    Args.notNull(usages, "usages");

    List<Asn1Oid> list = new ArrayList<>(usages);
    list.sort(Comparator.comparing(Asn1Oid::getId));
    list = removeDuplication(list);

    return new ExtendedKeyUsage(list.toArray(new Asn1Oid[0]));
  }

  // sort the list and remove duplicated OID.
  private static List<Asn1Oid> removeDuplication(List<Asn1Oid> oids) {
    List<Asn1Oid> res = new ArrayList<>(oids.size());
    for (Asn1Oid n : oids) {
      if (!res.contains(n)) {
        res.add(n);
      }
    }
    return res;
  }

  /**
   * Build the certificate path. Cross certificate will not be considered.
   * @param targetCert certificate for which the certificate path will be built
   * @param certs collection of certificates.
   * @return the certificate path
   */
  public static X509Cert[] buildCertPath(X509Cert targetCert, Collection<X509Cert> certs) {
    return buildCertPath(targetCert, certs, true);
  }

  /**
   * Build the certificate path. Cross certificate will not be considered.
   * @param targetCert certificate for which the certificate path will be built
   * @param certs collection of certificates.
   * @param includeTargetCert whether to include {@code targetCert} in the result.
   * @return the certificate path
   */
  public static X509Cert[] buildCertPath(
      X509Cert targetCert, Collection<X509Cert> certs, boolean includeTargetCert) {
    return buildCertPath(targetCert, certs, null, includeTargetCert);
  }

  public static X509Cert[] buildCertPath(
      X509Cert targetCert, Collection<X509Cert> certs,
      Collection<X509Cert> trustanchors, boolean includeTargetCert) {
    Args.notNull(targetCert, "cert");

    if (trustanchors == null) {
      trustanchors = Collections.emptySet();
    }

    if (!trustanchors.isEmpty()) {
      Set<X509Cert> coll = certs == null ? new HashSet<>() : new HashSet<>(certs);

      coll.addAll(trustanchors);
      certs = coll;
    }

    List<X509Cert> certChain = new LinkedList<>();
    certChain.add(targetCert);
    if (certs != null && !targetCert.isSelfSigned()) {
      while (true) {
        X509Cert caCert = getCaCertOf(certChain.get(certChain.size() - 1), certs);
        if (caCert == null) {
          break;
        }

        certChain.add(caCert);
        if (caCert.isSelfSigned() || trustanchors.contains(caCert)) {
          // reaches root self-signed certificate or trustanchor
          break;
        }
      }
    }

    if (!trustanchors.isEmpty()) {
      if (!trustanchors.contains(certChain.get(certChain.size() - 1))) {
        return null;
      }
    }

    final int n = certChain.size();
    if (n == 1) {
      return includeTargetCert ? certChain.toArray(new X509Cert[0]) : null;
    }

    if (!includeTargetCert) {
      certChain.remove(0);
    }

    return certChain.toArray(new X509Cert[0]);
  } // method buildCertPath

  public static String encodeCertificates(X509Cert[] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    byte[][] certchainBytes = new byte[certchain.length][];
    for (int i = 0; i < certchain.length; i++) {
      certchainBytes[i] = certchain[i].getEncoded();
    }
    return encodeCertificates(certchainBytes);
  }

  public static String encodeCertificates(byte[][] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (byte[] bytes : certchain) {
      sb.append(StringUtil.toUtf8String(PemEncoder.encode(bytes, PemEncoder.PemLabel.CERTIFICATE)));
    }
    return sb.toString();
  }

  public static List<X509Cert> listCertificates(String encodedCerts)
      throws CertificateException, IOException {
    List<X509Cert> certs = new LinkedList<>();
    try (BufferedReader reader = new BufferedReader(new StringReader(encodedCerts));
        ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (BEGIN_CERTIFICATE.equals(line)) {
          bout.reset();
        } else if (END_CERTIFICATE.equals(line)) {
          certs.add(parseCert(bout.toByteArray()));
          bout.reset();
        } else {
          bout.write(StringUtil.toUtf8Bytes(line));
        }
      }
    }
    return certs;
  }

  private static X509Cert getCaCertOf(X509Cert cert, Collection<X509Cert> caCerts) {
    if (notNull(cert, "cert").isSelfSigned()) {
      return null;
    }

    for (X509Cert caCert : caCerts) {
      if (!issues(caCert, cert)) {
        continue;
      }

      try {
        cert.verify(caCert.publicKey());
        return caCert;
      } catch (Exception ex) {
        LOG.warn("could not verify certificate: {}", ex.getMessage());
      }
    }

    return null;
  }

  public static boolean issues(X509Cert issuerCert, X509Cert cert) {
    Args.notNull(cert, "cert");

    // check basicConstraints
    int pathLen = notNull(issuerCert, "issuerCert").basicConstraints();
    if (pathLen == -1) {
      // issuerCert is not a CA certificate
      return false;
    }

    // assert issuerCert.pathLen > cert.pathLen
    if (pathLen != Integer.MAX_VALUE) {
      if (pathLen <= cert.basicConstraints()) {
        return false;
      }
    }

    boolean issues = issuerCert.subject().equals(cert.issuer());
    if (issues) {
      byte[] ski = issuerCert.subjectKeyId();
      byte[] aki;
      try {
        aki = cert.authorityKeyId();
      } catch (CodecException e) {
        return false;
      }
      if (ski != null && aki != null) {
        issues = Arrays.equals(ski, aki);
      }
    }

    if (issues) {
      long issuerNotBefore = issuerCert.notBefore().toEpochMilli();
      long issuerNotAfter  = issuerCert.notAfter().toEpochMilli();
      long notBefore = cert.notBefore().toEpochMilli();
      issues = notBefore <= issuerNotAfter && notBefore >= issuerNotBefore;
    }

    return issues;
  } // method issues

  public static SubjectPublicKeyInfo toRfc3279Style(SubjectPublicKeyInfo publicKeyInfo) {
    try {
      KeySpec keySpec = KeySpec.ofPublicKey(publicKeyInfo);
      if (keySpec == null || publicKeyInfo.getAlgorithm().equals(keySpec.algorithmIdentifier())) {
        return publicKeyInfo;
      }

      return new SubjectPublicKeyInfo(keySpec.algorithmIdentifier(),
                publicKeyInfo.getSubjectPublicKey());
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  } // method toRfc3279Style

  public static String cutText(String text, int maxLen) {
    if (notNull(text, "text").length() <= maxLen) {
      return text;
    }
    return StringUtil.concat(text.substring(0, maxLen - 13), "...skipped...");
  }

  public static String cutX500Name(X500Name name, int maxLen) {
    return cutText(x500NameText(name), maxLen);
  }

  public static Extension createExtnSubjectAltName(List<String> taggedValues, boolean critical)
      throws PkixException {
    GeneralNames names = createGeneralNames(taggedValues);
    if (names == null) {
      return null;
    }

    return Extension.ofSubjectAlternativeName(critical, names);
  } // method createExtnSubjectAltName

  public static Extension createExtnSubjectInfoAccess(
      List<String> accessMethodAndLocations, boolean critical) throws PkixException {
    if (CollectionUtil.isEmpty(accessMethodAndLocations)) {
      return null;
    }

    List<AccessDescription> vector = new ArrayList<>(accessMethodAndLocations.size());
    for (String accessMethodAndLocation : accessMethodAndLocations) {
      vector.add(createAccessDescription(accessMethodAndLocation));
    }

    SubjectInfoAccessSyntax syntax = new SubjectInfoAccessSyntax(vector);
    return Extension.ofSubjectInfoAccess(critical, syntax);
  } // method createExtnSubjectInfoAccess

  private static AccessDescription createAccessDescription(String accessMethodAndLocation)
      throws PkixException {
    ConfPairs pairs;
    try {
      pairs = new ConfPairs(notNull(accessMethodAndLocation, "accessMethodAndLocation"));
    } catch (IllegalArgumentException ex) {
      throw new PkixException("invalid accessMethodAndLocation " + accessMethodAndLocation);
    }

    Set<String> oids = pairs.names();
    if (oids == null || oids.size() != 1) {
      throw new PkixException("invalid accessMethodAndLocation " + accessMethodAndLocation);
    }

    String accessMethodS = oids.iterator().next();
    String taggedValue = pairs.value(accessMethodS);
    Asn1Oid accessMethod = new Asn1Oid(accessMethodS);

    GeneralName location = createGeneralName(taggedValue);
    return new AccessDescription(accessMethod, location);
  } // method createAccessDescription

  private static GeneralNames createGeneralNames(List<String> taggedValues)
      throws PkixException {
    if (CollectionUtil.isEmpty(taggedValues)) {
      return null;
    }

    int len = taggedValues.size();
    GeneralName[] names = new GeneralName[len];
    for (int i = 0; i < len; i++) {
      names[i] = createGeneralName(taggedValues.get(i));
    }
    return new GeneralNames(names);
  } // method createGeneralNames

  /**
  * Creates {@link GeneralName} from the tagged value.
  * @param taggedValue [tag]value, and the value for tags otherName and
   *       ediPartyName is type=value.
  * @return the created {@link GeneralName}
  * @throws PkixException
  *         if the {@code taggedValue} is invalid.
  */
  private static GeneralName createGeneralName(String taggedValue) throws PkixException {
    String tagS = null;
    String value = null;
    if (Args.notBlank(taggedValue, "taggedValue").charAt(0) == '[') {
      int idx = taggedValue.indexOf(']', 1);
      if (idx > 1 && idx < taggedValue.length() - 1) {
        tagS = taggedValue.substring(1, idx).toLowerCase();
        value = taggedValue.substring(idx + 1);
      }
    }

    int tag = getTag(tagS);

    switch (tag) {
      case GeneralName.tag_otherName: {
        if (value == null) {
          throw new PkixException("invalid otherName: null");
        }

        int idxSep = value.indexOf("=");
        if (idxSep == -1 || idxSep == 0 || idxSep == value.length() - 1) {
          throw new PkixException("invalid otherName " + value);
        }

        String otherTypeOid = value.substring(0, idxSep);
        Asn1Oid type = new Asn1Oid(otherTypeOid);
        String otherValue = value.substring(idxSep + 1);

        String prefix = null;
        if (StringUtil.startsWithIgnoreCase(otherValue, "printablestring:")) {
          // "printablestring:".length() = 16
          prefix = "printablestring:";
          otherValue = otherValue.substring(16);
        } else if (StringUtil.startsWithIgnoreCase(otherValue, "utf8string:")) {
          // "utf8string:".length() = 11
          prefix = "utf8string:";
          otherValue = otherValue.substring(11);
        } else if (StringUtil.startsWithIgnoreCase(otherValue, "ia5string:")) {
          // "ia5string:".length() = 11
          prefix = "ia5string:";
          otherValue = otherValue.substring(11);
        } else if (StringUtil.startsWithIgnoreCase(otherValue, "bmpstring:")) {
          // "bmpstring:".length() = 11
          prefix = "bmpstring:";
          otherValue = otherValue.substring(11);
        }

        OtherName on;
        if (type.equals(X509OIDs.id_on_MACAddress)) {
          try {
            on = OtherName.ofMacAddress(Hex.decode(otherValue));
          } catch (CodecException e) {
            throw new PkixException("invalid MACAddress: '" + otherValue + "'", e);
          }
        } else if (type.equals(X509OIDs.id_on_SmtpUTF8Mailbox)) {
          try {
            on = OtherName.ofSmtpUTF8Mailbox(otherValue);
          } catch (CodecException e) {
            throw new PkixException("invalid SmtpUTF8Mailbox: '" + otherValue + "'", e);
          }
        } else if (type.equals(SpdmOIDs.id_DMTF_device_info)) {
          try {
            on = OtherName.ofDmtfDeviceInfo(new DmtfDeviceInfo(otherValue));
          } catch (CodecException e) {
            throw new PkixException("invalid DMTF device info: '" + otherValue + "'", e);
          }
        } else if (type.equals(ExtensionOIDs.id_microsoft_objectSid)) {
          on = OtherName.ofMicrosoftObjectSid(otherValue.getBytes(StandardCharsets.US_ASCII));
        } else if (type.equals(X509OIDs.id_on_hardwareModuleName)) {
          throw new PkixException("Specifying otherName in this way " +
              "is not supported for id_on_hardwareModuleName unsupported");
        } else if (type.equals(TcgOIDs.tcg_at_platformIdentifier)) {
          throw new PkixException("Specifying otherName in this way " +
              "is not supported for tcg_at_platformIdentifier unsupported");
        } else {
          Asn1Primitive asn1Value;
          if (prefix == null) {
            asn1Value = new Asn1Utf8String(otherValue);
          } else if (prefix.equals("printablestring:")) {
            asn1Value = new Asn1PrintableString(otherValue);
          } else if (prefix.equals("utf8string:")) {
            asn1Value = new Asn1Utf8String(otherValue);
          } else if (prefix.equals("ia5string:")) {
            asn1Value = new Asn1IA5String(otherValue);
          } else { // if (prefix.equals("bmpstring:")) {
            asn1Value = new Asn1BmpString(otherValue);
          }

          try {
            on = OtherName.create(type, asn1Value);
          } catch (CodecException e) {
            throw new PkixException("could not create OtherName", e);
          }
        }

        return GeneralName.ofOtherName(on);
      }
      case GeneralName.tag_rfc822Name:
      case GeneralName.tag_uri:
      case GeneralName.tag_iPAddress:
      case GeneralName.tag_dNSName:
      case GeneralName.tag_registeredID:
      case GeneralName.tag_directoryName:
        return GeneralName.ofTagName(tag, value);
      case GeneralName.tag_ediPartyName: {
        if (value == null) {
          throw new PkixException("invalid ediPartyName: null");
        }

        int idxSep = value.indexOf("=");
        if (idxSep == -1 || idxSep == value.length() - 1) {
          throw new PkixException("invalid ediPartyName " + value);
        }
        String nameAssigner = (idxSep == 0) ? null : value.substring(0, idxSep);
        String partyName = value.substring(idxSep + 1);
        EDIPartyName edi = new EDIPartyName(nameAssigner, partyName);
        return GeneralName.ofEdiPartyName(edi);
      }
      default:
        throw new IllegalStateException("unsupported tag " + tag);
    } // end switch (tag)
  } // method createGeneralName

  private static int getTag(String tagS) throws PkixException {
    try {
      if ("0".equals(tagS) || "othername".equals(tagS)) {
        return 0;
      } else if ("1".equals(tagS) || "email".equals(tagS) || "rfc822".equals(tagS)) {
        return 1;
      } else if ("2".equals(tagS) || "dns".equals(tagS) || "dnsname".equals(tagS)) {
        return 2;
      } else if ("4".equals(tagS) || "dirname".equals(tagS)) {
        return 4;
      } else if ("5".equals(tagS) || "edi".equals(tagS)) {
        return 5;
      } else if ("6".equals(tagS) || "uri".equals(tagS)) {
        return 6;
      } else if ("7".equals(tagS) || "ip".equals(tagS) || "ipaddress".equals(tagS)) {
        return 7;
      } else if ("8".equals(tagS) || "rid".equals(tagS) || "registeredid".equals(tagS)) {
        return 8;
      } else {
        throw new PkixException("unknown tag " + tagS);
      }
    } catch (NumberFormatException ex) {
      throw new PkixException("invalid tag '" + tagS + "'");
    }
  }

  public static String formatCert(X509Cert cert, boolean verbose) {
    if (cert == null) {
      return "  null";
    }

    StringBuilder sb = new StringBuilder(verbose ? 2000 : 100);
    if (!verbose) {
      sb.append("  issuer:       ").append(x500NameText(cert.issuer())).append('\n');
      sb.append("  serialNumber: ").append(LogUtil.formatCsn(cert.serialNumber())).append('\n');
      sb.append("  subject:      ").append(x500NameText(cert.subject())).append('\n');
      sb.append("  notBefore:    ").append(cert.notBefore()).append("\n");
      sb.append("  notAfter:     ").append(cert.notAfter());
    } else {
      sb.append(cert.toString(1));
      sb.append("\n  encoded:      ").append(Base64.getNoPaddingEncoder()
          .encodeToString(cert.getEncoded()));
    }

    return sb.toString();
  } // method formatCert

  public static Attribute getAttribute(CertificationRequest csr, Asn1Oid type) {
    Args.notNull(type, "type");
    Attribute.Set0 attrs = notNull(csr, "csr").getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = attrs.get(i);
      if (type.equals(attr.getAttrType())) {
        return attr;
      }
    }
    return null;
  } // method getChallengePassword

  public static List<X509Cert> parseCerts(List<FileOrBinary> certsConf)
      throws InvalidConfException {
    if (CollectionUtil.isEmpty(certsConf)) {
      return Collections.emptyList();
    }

    List<X509Cert> certs = new ArrayList<>(certsConf.size());

    for (FileOrBinary m : certsConf) {
      try {
        X509Cert cert = parseCert(m.readContent());
        certs.add(cert);
      } catch (CertificateException | IOException ex) {
        String msg = "could not parse the certificate";
        if (m.file() != null) {
          msg += " " + m.file();
        }
        throw new InvalidConfException(msg, ex);
      }
    }

    return certs;
  }

  public static void assertCsrAndCertMatch(
      CertificationRequest csr, Certificate targetCert, boolean caCertRequired)
      throws XiSecurityException {
    try {
      if (!Arrays.equals(csr.getSubject().getEncoded(), targetCert.getSubject().getEncoded())) {
        throw new XiSecurityException("CSR and certificate do not have the same subject");
      }

      if (!Arrays.equals(csr.getSubjectPKInfo().getEncoded(),
          targetCert.getSubjectPublicKeyInfo().getEncoded())) {
        throw new XiSecurityException(
            "CSR and certificate do not have the same SubjectPublicKeyInfo");
      }

      if (caCertRequired) {
        Extension extn = targetCert.getTBSCertificate().getExtension(
                          ExtensionOIDs.basicConstraints);
        BasicConstraints bc = extn == null ? null : extn.getBasicConstraints();
        if (bc == null || !bc.isCA()) {
          throw new XiSecurityException("targetCert is not a CA certificate");
        }
      }
    } catch (RuntimeException ex) {
      throw new XiSecurityException("error while encoding Subject or SubjectPublicKeyInfo");
    }
  }

  public static byte[] extractCertSubject(byte[] certBytes) {
    return extractCertField(certBytes, "subject");
  }

  public static byte[] extractCertIssuer(byte[] certBytes) {
    return extractCertField(certBytes, "issuer");
  }

  public static long extractCertNotAfter(byte[] certBytes) throws CodecException {
    return extractTime(certBytes, "notAfter");
  }

  private static long extractTime(byte[] certBytes, String fieldName) throws CodecException {
    byte[] bytes = extractCertField(certBytes, fieldName);
    Time time = Time.fromEncoded(bytes);
    return time.time().getEpochSecond();
  }

  private static byte[] extractCertField(byte[] certBytes, String fieldName) {
    try (BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(certBytes))) {
      // SEQUENCE of Certificate
      Asn1StreamParser.skipTagLen(is);

      // SEQUENCE OF TBSCertificate
      Asn1StreamParser.skipTagLen(is);

      // #num = 3: version, serialNumber, signature
      int numFields = 3;
      for (int i = 0; i < numFields; i++) {
        Asn1StreamParser.skipField(is);
      }

      // issuer
      if ("issuer".equalsIgnoreCase(fieldName)) {
        return Asn1StreamParser.readBlock(Asn1StreamParser.TAG_CONSTRUCTED_SEQUENCE, is, "issuer");
      } else {
        Asn1StreamParser.skipField(is);
      }

      // Validity
      if ("notBefore".equalsIgnoreCase(fieldName) || "notAfter".equalsIgnoreCase(fieldName)) {
        Asn1StreamParser.skipTagLen(is);

        // notBefore
        if ("notBefore".equalsIgnoreCase(fieldName)) {
          return Asn1StreamParser.readBlock(is, "notBefore");
        } else {
          Asn1StreamParser.skipField(is);
        }

        // notAfter
        if ("notAfter".equalsIgnoreCase(fieldName)) {
          return Asn1StreamParser.readBlock(is, "notAfter");
        } else {
          Asn1StreamParser.skipField(is);
        }
      } else {
        Asn1StreamParser.skipField(is);
      }

      if ("subject".equalsIgnoreCase(fieldName)) {
        return Asn1StreamParser.readBlock(Asn1StreamParser.TAG_CONSTRUCTED_SEQUENCE, is, "subject");
      }
    } catch (IOException e) {
      throw new RuntimeException("invalid certificate", e);
    }

    throw new IllegalArgumentException("unknown fieldName " + fieldName);
  }

  private static String valueToString(Asn1Primitive value) {
    StringBuilder vBuf = new StringBuilder();

    if (value instanceof AbstractAsn1String) { // && !(value instanceof ASN1UniversalString))
      String v = ((AbstractAsn1String)value).getString();
      if (!v.isEmpty() && v.charAt(0) == '#') {
        vBuf.append('\\');
      }

      vBuf.append(v);
    } else {
      vBuf.append('#');
      // -DM Hex.toHexString
      vBuf.append(Hex.encode(value.getEncoded(Asn1Encoding.DER)));
    }

    // Escape in a single linear pass into a fresh builder. The previous implementation escaped by
    // inserting a backslash into the buffer it was scanning (O(n) per insert), so a value of n
    // RFC 4514 special characters - or n leading/trailing spaces - cost ~n^2/2 character moves: a
    // CPU-exhaustion vector for an attacker-supplied large RDN reached via
    // X500Name.toString()/equals()/hashCode(). Output is unchanged.
    int len = vBuf.length();

    // A leading "\#" (produced above when the value begins with '#') is emitted verbatim and the
    // leading-space escaping is suppressed, matching the original phase ordering.
    boolean hashPrefix = len >= 2 && vBuf.charAt(0) == '\\' && vBuf.charAt(1) == '#';

    int firstNonSpace = 0;
    while (firstNonSpace < len && vBuf.charAt(firstNonSpace) == ' ') {
      firstNonSpace++;
    }

    int lastNonSpace = len - 1;
    while (lastNonSpace >= 0 && vBuf.charAt(lastNonSpace) == ' ') {
      lastNonSpace--;
    }

    StringBuilder out = new StringBuilder(len + 16);
    int index = 0;
    if (hashPrefix) {
      out.append("\\#");
      index = 2;
    }

    for (; index < len; index++) {
      char c = vBuf.charAt(index);
      boolean escape;
      switch (c) {
        case ',':
        case '"':
        case '\\':
        case '+':
        case '=':
        case '<':
        case '>':
        case ';':
          escape = true;
          break;
        case ' ':
          // leading spaces escaped only without a "\#" prefix; trailing spaces always escaped.
          escape = (!hashPrefix && index < firstNonSpace) || index > lastNonSpace;
          break;
        default:
          escape = false;
          break;
      }

      if (escape) {
        out.append('\\');
      }

      out.append(c);
    }

    return out.toString();
  }

}
