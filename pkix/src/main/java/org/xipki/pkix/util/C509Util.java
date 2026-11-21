// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.asn1.x500.RDN;
import org.xipki.asn1.x500.X500Name;
import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.base.C509ObjectId;
import org.xipki.c509.base.C509OtherName;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509ExtKeyUsageSyntax;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509InfoAccess;
import org.xipki.c509.ext.C509AccessDescription;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.codec.Base64;
import org.xipki.codec.Hex;
import org.xipki.codec.asn1.Asn1BmpString;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.c509.name.C509Name;
import org.xipki.c509.name.C509RdnAttribute;
import org.xipki.codec.c509.C509SubjectPublicKeyInfo;
import org.xipki.c509.registry.ConstRDNAttributeType;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.ConfPairs;
import org.xipki.codec.util.IoUtil;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.C509Crl;
import org.xipki.pkix.cert.KeyUsage;
import org.xipki.util.conf.FileOrBinary;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.CollectionUtil;
import org.xipki.util.misc.CompareUtil;
import org.xipki.util.misc.LogUtil;
import org.xipki.util.misc.PemEncoder;

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
public class C509Util {

  private static final Logger LOG = LoggerFactory.getLogger(C509Util.class);

  private static final byte[] BEGIN_PEM = StringUtil.toUtf8Bytes("-----BEGIN");

  private static final String BEGIN_CERTIFICATE = "-----BEGIN C509 CERTIFICATE-----";

  private static final String END_CERTIFICATE   = "-----END C509 CERTIFICATE-----";

  private C509Util() {
  }

  public static byte[] toDerEncoded(byte[] bytes) {
    return X509Util.toDerEncoded(bytes);
  }

  public static String getCommonName(C509Name name) {
    C509RdnAttribute rdn =
        notNull(name, "name").getFirstAttribute(ConstRDNAttributeType.commonName);
    return (rdn == null) ? null : rdn.attributeValue().asText();
  } // method getCommonName

  public static C509Name reverse(C509Name name) {
    C509RdnAttribute[] orig = notNull(name, "name").getAttributes();
    final int n = orig.length;
    C509RdnAttribute[] newRdn = new C509RdnAttribute[n];
    for (int i = 0; i < n; i++) {
      newRdn[i] = orig[n - 1 - i];
    }
    return new C509Name(newRdn);
  }

  public static C509Cert parseCert(File file) throws IOException, CertificateException {
    return parseCert(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static List<C509Cert> parseCerts(byte[] certsBytes)
      throws IOException, CertificateException {
    try (InputStream is = new ByteArrayInputStream(certsBytes)) {
      return parseCerts(is);
    }
  }

  public static List<C509Cert> parseCerts(File certsFile) throws IOException, CertificateException {
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
  private static List<C509Cert> parseCerts(InputStream certsStream)
      throws IOException, CertificateException {
    List<C509Cert> certs = new LinkedList<>();
    try (PemReader pemReader = new PemReader(
        new InputStreamReader(certsStream, StandardCharsets.UTF_8))) {
      PemObject pemObj;
      while ((pemObj = pemReader.readPemObject()) != null) {
        if (isCertPemType(pemObj.getType())) {
          certs.add(parseCert(pemObj.getContent()));
        }
      }
    }
    return certs;
  }

  // accepts also the label CERTIFICATE, which was used by earlier versions
  private static boolean isCertPemType(String type) {
    return PemEncoder.PemLabel.C509_CERTIFICATE.type().equalsIgnoreCase(type)
        || "CERTIFICATE".equalsIgnoreCase(type);
  }

  public static C509Cert parseCert(byte[] bytes) throws CertificateEncodingException {
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

          if (isCertPemType(obj.getType())) {
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
      byte[] derBytes = X509Util.toDerEncoded(certBytes);
      return new C509Cert(C509Certificate.parse(derBytes));
    } catch (CodecException ex) {
      throw new CertificateEncodingException("error decoding certificate: " + ex.getMessage(), ex);
    }
  }

  public static C509CertificationRequest parseCsr(File file) throws IOException {
    return parseCsr(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  public static C509CertificationRequest parseCsr(byte[] csrBytes) throws IOException {
    try {
      return C509CertificationRequest.parse(X509Util.toDerEncoded(notNull(csrBytes, "csrBytes")));
    } catch (CodecException ex) {
      throw new IOException("invalid CSR bytes", ex);
    }
  }

  public static String toPemCert(C509Cert cert) {
    return StringUtil.toUtf8String(PemEncoder.encode(
        notNull(cert, "cert").getEncoded(), PemEncoder.PemLabel.C509_CERTIFICATE));
  }

  /**
   * Encodes a public key in PEM with the label {@code C509 PUBLIC KEY}
   * (draft-liao-cose-c509-additions, Section 6.5).
   */
  public static String toPemPublicKey(C509SubjectPublicKeyInfo publicKey) {
    return StringUtil.toUtf8String(PemEncoder.encode(
        notNull(publicKey, "publicKey").getEncoded(), PemEncoder.PemLabel.C509_PUBLIC_KEY));
  }

  public static C509SubjectPublicKeyInfo parsePublicKey(File file) throws IOException {
    return parsePublicKey(IoUtil.read(IoUtil.expandFilepath(notNull(file, "file"))));
  }

  /**
   * Parses a public key, either CBOR-encoded or in PEM with the label {@code C509 PUBLIC KEY}.
   *
   * @throws IOException if the bytes are no valid public key, or the PEM data contains no
   *         {@code C509 PUBLIC KEY}.
   */
  public static C509SubjectPublicKeyInfo parsePublicKey(byte[] bytes) throws IOException {
    byte[] encoded = null;
    if (notNull(bytes, "bytes").length >= BEGIN_PEM.length
        && CompareUtil.areEqual(bytes, 0, BEGIN_PEM, 0, BEGIN_PEM.length)) {
      try (PemReader r = new PemReader(new InputStreamReader(
          new ByteArrayInputStream(bytes), StandardCharsets.UTF_8))) {
        PemObject obj;
        while ((obj = r.readPemObject()) != null) {
          if (PemEncoder.PemLabel.C509_PUBLIC_KEY.type().equals(obj.getType())) {
            encoded = obj.getContent();
            break;
          }
        }
      }

      if (encoded == null) {
        throw new IOException("found no " + PemEncoder.PemLabel.C509_PUBLIC_KEY.type());
      }
    } else {
      encoded = bytes;
    }

    try {
      return C509SubjectPublicKeyInfo.parse(encoded);
    } catch (CodecException ex) {
      throw new IOException("invalid C509 public key: " + ex.getMessage(), ex);
    }
  }

  public static C509Crl parseCrl(File file) throws IOException, CRLException {
    return parseCrl(Files.readAllBytes(IoUtil.expandFilepath(notNull(file, "file")).toPath()));
  }

  public static C509Crl parseCrl(byte[] encodedCrl) throws CRLException {
    try {
      byte[] encoded = X509Util.toDerEncoded(notNull(encodedCrl, "encodedCrl"));
      return new C509Crl(org.xipki.c509.crl.C509CertificateList.parse(encoded), encoded);
    } catch (CodecException ex) {
      throw new CRLException("the given one is not a valid X.509 CRL");
    }
  }

  public static String nameText(C509Name name) {
    StringBuilder buf = new StringBuilder(20);
    notNull(name, "name").toString(buf, 0);
    return buf.toString();
  }

  public static long fpCanonicalizedName(C509Name name) {
    return FpIdCalculator.hash(StringUtil.toUtf8Bytes(canonicalizeName(notNull(name, "name"))));
  }

  public static String canonicalizeName(C509Name name) {
    long[] tmpTypes = notNull(name, "name").attributeTypes();
    int len = tmpTypes.length;
    List<Long> types = new ArrayList<>(len);
    for (long type : tmpTypes) {
      types.add(type);
    }

    Collections.sort(types);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      long type = types.get(i);
      if (i > 0) {
        sb.append(",");
      }
      sb.append(type).append("=");
      C509RdnAttribute[] rdns = name.getAttribute(type);

      List<String> values = new ArrayList<>(1);
      for (C509RdnAttribute rdn : rdns) {
        values.add(rdn.attributeValueAsText());
      }

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

  public static C509KeyUsage createKeyUsage(Set<KeyUsage> usages) {
    Args.notEmpty(usages, "usages");

    C509KeyUsage[] singleUsages = new C509KeyUsage[usages.size()];
    int i = 0;
    for (KeyUsage keyUsage : usages) {
      singleUsages[i++] = keyUsage.c509();
    }

    return C509KeyUsage.of(singleUsages);
  }

  public static C509ExtKeyUsageSyntax createExtendedUsage(Collection<Long> usages) {
    Args.notNull(usages, "usages");

    List<Long> list = new ArrayList<>(usages);
    Collections.sort(list);
    list = removeDuplication(list);

    return new C509ExtKeyUsageSyntax(list);
  }

  // sort the list and remove duplicated OID.
  private static List<Long> removeDuplication(List<Long> oids) {
    List<Long> res = new ArrayList<>(oids.size());
    for (Long n : oids) {
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
  public static C509Cert[] buildCertPath(C509Cert targetCert, Collection<C509Cert> certs) {
    return buildCertPath(targetCert, certs, true);
  }

  /**
   * Build the certificate path. Cross certificate will not be considered.
   * @param targetCert certificate for which the certificate path will be built
   * @param certs collection of certificates.
   * @param includeTargetCert whether to include {@code targetCert} in the result.
   * @return the certificate path
   */
  public static C509Cert[] buildCertPath(
      C509Cert targetCert, Collection<C509Cert> certs, boolean includeTargetCert) {
    return buildCertPath(targetCert, certs, null, includeTargetCert);
  }

  public static C509Cert[] buildCertPath(
      C509Cert targetCert, Collection<C509Cert> certs,
      Collection<C509Cert> trustanchors, boolean includeTargetCert) {
    Args.notNull(targetCert, "cert");

    if (trustanchors == null) {
      trustanchors = Collections.emptySet();
    }

    if (!trustanchors.isEmpty()) {
      Set<C509Cert> coll = certs == null ? new HashSet<>() : new HashSet<>(certs);

      coll.addAll(trustanchors);
      certs = coll;
    }

    List<C509Cert> certChain = new LinkedList<>();
    certChain.add(targetCert);
    if (certs != null && !targetCert.isSelfSigned()) {
      while (true) {
        C509Cert caCert = getCaCertOf(certChain.get(certChain.size() - 1), certs);
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
      return includeTargetCert ? certChain.toArray(new C509Cert[0]) : null;
    }

    if (!includeTargetCert) {
      certChain.remove(0);
    }

    return certChain.toArray(new C509Cert[0]);
  } // method buildCertPath

  public static String encodePemCertificates(C509Cert[] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    byte[][] certchainBytes = new byte[certchain.length][];
    for (int i = 0; i < certchain.length; i++) {
      certchainBytes[i] = certchain[i].getEncoded();
    }
    return encodePemCertificates(certchainBytes);
  }

  public static String encodePemCertificates(byte[][] certchain) {
    if (CollectionUtil.isEmpty(certchain)) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (byte[] bytes : certchain) {
      sb.append(StringUtil.toUtf8String(
          PemEncoder.encode(bytes, PemEncoder.PemLabel.C509_CERTIFICATE)));
    }
    return sb.toString();
  }

  public static List<C509Cert> listPemCertificates(String encodedCerts)
      throws CertificateException, IOException {
    List<C509Cert> certs = new LinkedList<>();
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

  private static C509Cert getCaCertOf(C509Cert cert, Collection<C509Cert> caCerts) {
    if (notNull(cert, "cert").isSelfSigned()) {
      return null;
    }

    for (C509Cert caCert : caCerts) {
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

  public static boolean issues(C509Cert issuerCert, C509Cert cert) {
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
      byte[] aki = cert.authorityKeyId();
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

  public static String cutC509Name(C509Name name, int maxLen) {
    return X509Util.cutText(nameText(name), maxLen);
  }

  public static C509Extension createExtnSubjectAltName(List<String> taggedValues, boolean critical)
      throws PkixException {
    C509AltName names = createAltName(taggedValues);
    if (names == null) {
      return null;
    }

    return new C509Extension(ConstExtensionId.subjectAltName, critical, names);
  } // method createExtnSubjectAltName

  public static C509Extension createExtnSubjectInfoAccess(
      List<String> accessMethodAndLocations, boolean critical) throws PkixException {
    if (CollectionUtil.isEmpty(accessMethodAndLocations)) {
      return null;
    }

    List<C509AccessDescription> vector = new ArrayList<>(accessMethodAndLocations.size());
    for (String accessMethodAndLocation : accessMethodAndLocations) {
      vector.add(createAccessDescription(accessMethodAndLocation));
    }

    C509InfoAccess syntax = new C509InfoAccess(vector);
    return new C509Extension(ConstExtensionId.subjectInfoAccess, critical, syntax);
  } // method createExtnSubjectInfoAccess

  private static C509AccessDescription createAccessDescription(String accessMethodAndLocation)
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
    String location = pairs.value(accessMethodS);
    Integer code = ConstAccessMethod.code(accessMethodS);
    if (code == null) {
      throw new PkixException("invalid accessMethod " + accessMethodS);
    }

    return new C509AccessDescription(code, location);
  } // method createAccessDescription

  private static C509AltName createAltName(List<String> taggedValues)
      throws PkixException {
    if (CollectionUtil.isEmpty(taggedValues)) {
      return null;
    }

    int len = taggedValues.size();
    C509GeneralName[] names = new C509GeneralName[len];
    for (int i = 0; i < len; i++) {
      names[i] = createGeneralName(taggedValues.get(i));
    }
    return new C509AltName(C509GeneralNames.of(names));
  } // method createGeneralNames

  /**
  * Creates {@link C509GeneralName} from the tagged value.
  * @param taggedValue [tag]value, and the value for tags otherName and
   *       ediPartyName is type=value.
  * @return the created {@link C509GeneralName}
  * @throws PkixException
  *         if the {@code taggedValue} is invalid.
  */
  private static C509GeneralName createGeneralName(String taggedValue) throws PkixException {
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
      case ConstGeneralNameTag.otherName:
      case ConstGeneralNameTag.hardwareModuleName: {
        if (value == null) {
          throw new PkixException("invalid otherName: null");
        }

        int idxSep = value.indexOf("=");
        if (idxSep == -1 || idxSep == 0 || idxSep == value.length() - 1) {
          throw new PkixException("invalid otherName '" + value + "'");
        }

        C509ObjectId type = C509ObjectId.of(value.substring(0, idxSep));
        String value2 = value.substring(idxSep + 1);

        byte[] encodedValue2;
        if (StringUtil.startsWithIgnoreCase(value2, "printablestring:")) {
          // "printablestring:".length() = 16
          encodedValue2 = new Asn1PrintableString(value2.substring(16)).getEncoded();
        } else if (StringUtil.startsWithIgnoreCase(value2, "utf8string:")) {
          // "utf8string:".length() = 11
          encodedValue2 = new Asn1Utf8String(value2.substring(11)).getEncoded();
        } else if (StringUtil.startsWithIgnoreCase(value2, "ia5string:")) {
          // "ia5string:".length() = 11
          encodedValue2 = new Asn1IA5String(value2.substring(11)).getEncoded();
        } else if (StringUtil.startsWithIgnoreCase(value2, "bmpstring:")) {
          // "bmpstring:".length() = 11
          encodedValue2 = new Asn1BmpString(value2.substring(11)).getEncoded();
        } else if (StringUtil.startsWithIgnoreCase(value2, "base64:")) {
          // "base64:".length() = 7
          encodedValue2 = Base64.decode(value2.substring(7));
        } else if (StringUtil.startsWithIgnoreCase(value2, "hex:")) {
          // "hex:".length() = 4
          encodedValue2 = Hex.decode(value2.substring(4));
        } else {
          throw new PkixException("invalid otherName '" + value + "'");
        }

        C509OtherName v = new C509OtherName(type, encodedValue2);

        return tag == ConstGeneralNameTag.otherName
            ? C509GeneralName.otherName(v) : C509GeneralName.hardwareModuleName(v);
      }
      case ConstGeneralNameTag.SmtpUTF8Mailbox:
        return C509GeneralName.smtpUtf8Mailbox(value);
      case ConstGeneralNameTag.MACAddress:
        return C509GeneralName.macAddress(Base64.decode(value));
      case ConstGeneralNameTag.rfc822Name:
        return C509GeneralName.rfc822(value);
      case ConstGeneralNameTag.uniformResourceIdentifier:
        return C509GeneralName.uri(value);
      case ConstGeneralNameTag.iPAddress:
        return C509GeneralName.ip(value);
      case ConstGeneralNameTag.dNSName:
        return C509GeneralName.dns(value);
      case ConstGeneralNameTag.registeredID:
        return C509GeneralName.registeredId(C509ObjectId.of(value));
      case ConstGeneralNameTag.directoryName:
        return C509GeneralName.directory(new C509Name(value));
      default:
        throw new IllegalStateException("unsupported tag " + tag);
    } // end switch (tag)
  } // method createGeneralName

  private static int getTag(String tagS) throws PkixException {
    try {
      if ("0".equals(tagS) || "othername".equals(tagS)) {
        return 0;
      } else if ("-3".equals(tagS) || "macaddress".equals(tagS) || "on-macaddress".equals(tagS)) {
        return -3;
      } else if ("-2".equals(tagS) || "smtputf8mailbox".equals(tagS)
          || "on-smtputf8mailbox".equals(tagS)) {
        return -2;
      } else if ("-1".equals(tagS) || "hardwaremodulename".equals(tagS)
          || "on-hardwaremodulename".equals(tagS)) {
        return -1;
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

  public static String formatCert(C509Cert cert, boolean verbose) {
    if (cert == null) {
      return "  null";
    }

    StringBuilder sb = new StringBuilder(verbose ? 2000 : 100);
    if (!verbose) {
      sb.append("  issuer:       ").append(nameText(cert.issuer())).append('\n');
      sb.append("  serialNumber: ").append(LogUtil.formatCsn(cert.serialNumber())).append('\n');
      sb.append("  subject:      ").append(nameText(cert.subject())).append('\n');
      sb.append("  notBefore:    ").append(cert.notBefore()).append("\n");
      sb.append("  notAfter:     ").append(cert.notAfter());
    } else {
      sb.append(cert.toString(1));
      sb.append("\n  encoded:      ").append(Base64.getNoPaddingEncoder()
          .encodeToString(cert.getEncoded()));
    }

    return sb.toString();
  } // method formatCert

  public static C509Attribute getAttribute(C509CertificationRequest csr, long type) {
    Args.notNull(type, "type");
    return csr.body().attributes().first(type);
  }

  public static List<C509Cert> parseCerts(List<FileOrBinary> certsConf)
      throws InvalidConfException {
    return parseCerts(certsConf, null);
  }

  /**
   * Parses the certificates.
   * @param certsConf the certificates, or the files containing them.
   * @param basedir the base directory, against which relative files are resolved. May be
   *                {@code null}.
   * @return the parsed certificates.
   * @throws InvalidConfException if a certificate could not be parsed.
   */
  public static List<C509Cert> parseCerts(List<FileOrBinary> certsConf, String basedir)
      throws InvalidConfException {
    if (CollectionUtil.isEmpty(certsConf)) {
      return Collections.emptyList();
    }

    List<C509Cert> certs = new ArrayList<>(certsConf.size());

    for (FileOrBinary m : certsConf) {
      try {
        C509Cert cert = parseCert(m.readContent(basedir));
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
      C509CertificationRequest csr, C509Certificate targetCert, boolean caCertRequired)
      throws XiSecurityException {
    if (!Arrays.equals(csr.body().subject().getEncoded(), targetCert.subject().getEncoded())) {
      throw new XiSecurityException("CSR and certificate do not have the same subject");
    }

    if (!Arrays.equals(csr.body().subjectPublicKey().getEncoded(),
        targetCert.subjectPublicKey().getEncoded())) {
      throw new XiSecurityException(
          "CSR and certificate do not have the same SubjectPublicKeyInfo");
    }

    if (caCertRequired) {
      C509BasicConstraints bc = targetCert.extensions().basicConstraints();
      if (bc == null || !bc.isCA()) {
        throw new XiSecurityException("targetCert is not a CA certificate");
      }
    }
  }

}
