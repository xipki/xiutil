// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkix.util;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.AuthorityKeyIdentifier;
import org.xipki.asn1.x509.BasicConstraints;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.ExtendedKeyUsage;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.asn1.x509.KeyUsage;
import org.xipki.asn1.x509.SubjectKeyIdentifier;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.C509CertificateBuilder;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509ExtKeyUsageSyntax;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.x509.id.KeyPurposeOIDs;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.IPAddressUtil;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.pkcs12.C509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.util.misc.PemEncoder;
import org.xipki.pkix.pkcs12.X509KeyPairWithSubjectPublicKeyInfo;
import org.xipki.pkix.pkcs12.KeystoreGenerationParameters;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.Signer;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.misc.RandomUtil;
import org.xipki.util.conf.Validity;
import org.xipki.codec.util.IoUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.xipki.codec.util.Args.notEmpty;

/**
 * Generate Certs.
 *
 * @author Lijun Liao (xipki)
 */
public class GenerateCerts {

  private enum CertFormat {
    C509,
    X509;
  }

  private static class CertChoice {

    private final X509Cert x509;

    private final C509Cert c509;

    public CertChoice(X509Cert x509) {
      this.x509 = Args.notNull(x509, "x509");
      this.c509 = null;
    }

    public CertChoice(C509Cert c509) {
      this.x509 = null;
      this.c509 = Args.notNull(c509, "c509");
    }

    public byte[] getEncoded() {
      return (x509 != null) ? x509.getEncoded() : c509.getEncoded();
    }

    public PublicKey publicKey() {
      return (x509 != null) ? x509.publicKey() : c509.publicKey();
    }

    public Instant notBefore() {
      return (x509 != null) ? x509.notBefore() : c509.notBefore();
    }

    public Instant notAfter() {
      return (x509 != null) ? x509.notAfter() : c509.notAfter();
    }

  }

  private static class Conf {

    private final List<SecretKeyConf> secretkeys;
    private final List<KeyCertConf> keycerts;
    private final List<KeyCertConf2> keycerts2;
    private final List<CertStore> certstores;

    public Conf(List<SecretKeyConf> secretkeys, List<KeyCertConf> keycerts,
                List<KeyCertConf2>  keycerts2,  List<CertStore>   certstores) {
      this.secretkeys = (secretkeys == null) ? Collections.emptyList() : secretkeys;
      this.keycerts   = (keycerts == null)   ? Collections.emptyList() : keycerts;
      this.keycerts2  = (keycerts2 == null)  ? Collections.emptyList() : keycerts2;
      this.certstores = (certstores == null) ? Collections.emptyList() : certstores;
      validate();
    }

    private void validate() {
      Set<String> caKeyCertNames = new HashSet<>();
      Set<String> keyCertNames = new HashSet<>();

      for (KeyCertConf m : this.keycerts) {
        String name = m.name;
        if ("certstore".equalsIgnoreCase(name)) {
          throw new IllegalArgumentException("Name 'keystore' is reserved and can not be used");
        }

        if (keyCertNames.contains(name)) {
          throw new IllegalArgumentException("Duplicated name " + name);
        }
        keyCertNames.add(name);

        if ("CA".equalsIgnoreCase((m.certType))) {
          caKeyCertNames.add(name);
        } else if (m.issuerName != null) {
          if (!caKeyCertNames.contains(m.issuerName)) {
            throw new IllegalArgumentException("Unknown issuer '" + m.issuerName + "'");
          }
        }
      }

      for (KeyCertConf2 m : this.keycerts2) {
        String name = m.name;
        if ("certstore".equalsIgnoreCase(name)) {
          throw new IllegalArgumentException("Name 'keystore' is reserved and can not be used");
        }

        if (keyCertNames.contains(name)) {
          throw new IllegalArgumentException("Duplicated name " + name);
        }
        keyCertNames.add(name);

        if (m.issuerName() != null) {
          if (!caKeyCertNames.contains(m.issuerName())) {
            throw new IllegalArgumentException("Unknown issuer '" + m.issuerName() + "'");
          }
        }
      }

      Set<String> keystoreNameSet = new HashSet<>();
      if (certstores != null) {
        for (CertStore m : certstores) {
          String name = m.name;
          if (keystoreNameSet.contains(name)) {
            throw new IllegalArgumentException("Duplicated certstore name " + name);
          }
          keystoreNameSet.add(name);

          for (String certName : m.keyCertNames) {
            if (!keyCertNames.contains(certName)) {
              throw new IllegalArgumentException("Unknown keycert name " + certName);
            }
          }
        }
      }

      if (secretkeys != null && secretkeys.size() > 1) {
        Set<String> keystoreNames = new HashSet<>();
        for (SecretKeyConf m : secretkeys) {
          if (keystoreNames.contains(m.name)) {
            throw new IllegalArgumentException("Duplicated secretkey name " + m.name);
          }
          keystoreNames.add(m.name);
        }
      }
    }

    public static Conf parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("secretkeys");
      List<SecretKeyConf> secretkeys = (list == null) ? null : SecretKeyConf.parseList(list);

      list = json.getList("keycerts");
      List<KeyCertConf> keycerts = (list == null) ? null : KeyCertConf.parseList(list);

      list = json.getList("keycerts2");
      List<KeyCertConf2> keycerts2 = (list == null) ? null : KeyCertConf2.parseList(list);

      list = json.getList("certstores");
      List<CertStore> cerstores = (list == null) ? null : CertStore.parseList(list);

      return new Conf(secretkeys, keycerts, keycerts2, cerstores);
    }

  }

  private static class CertStore {

    private final String name;

    private final String p12Password;

    private final List<String> keyCertNames;

    public CertStore(String name, String p12Password, List<String> keyCertNames) {
      this.name = Args.notBlank(name, "name");
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.keyCertNames = notEmpty(keyCertNames, "keyCertNames");
    }

    public static CertStore parse(JsonMap json) throws CodecException {
      return new CertStore(json.getNnString("name"),
          json.getString("p12Password"), json.getStringList("keyCertNames"));
    }

    public static List<CertStore> parseList(JsonList json) throws CodecException {
      List<CertStore> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class KeyCertConf {

    private final String name;
    private final String issuerName;
    private final String keyType;
    // C509, X509 (default)
    private final CertFormat certFormat;
    // CA, TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;
    private final String p12Password;

    public KeyCertConf(String name, String issuerName, String keyType, CertFormat certFormat,
                      String certType, String subject, String validity, String p12Password) {
      this.name = Args.notBlank(name, "name");
      this.keyType = Args.notBlank(keyType, "keyType");
      this.certFormat = certFormat == null ? CertFormat.X509 : certFormat;
      this.certType = Args.notBlank(certType, "certType");
      this.subject = Args.notBlank(subject, "subject");
      this.validity = Args.notBlank(validity, "validity");
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.issuerName = issuerName;

      if ("CA".equalsIgnoreCase(certType) && issuerName != null) {
        throw new IllegalArgumentException("CA shall not have non-null issuerName");
      }
    }

    public static KeyCertConf parse(JsonMap json) throws CodecException {
      return new KeyCertConf(json.getString("name"), json.getString("issuerName"),
          json.getString("keyType"), json.getEnum("certFormat", CertFormat.class),
          json.getString("certType"), json.getString("subject"),
          json.getString("validity"), json.getString("p12Password"));
    }

    public static List<KeyCertConf> parseList(JsonList json) throws CodecException {
      List<KeyCertConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class KeyCertConf2 {

    private final String name;
    private final String issuerName;
    private final String p12Password;
    private final List<SingleKeyCert> entries;

    public KeyCertConf2(String name, String issuerName, String p12Password,
                        List<SingleKeyCert> entries) {
      this.name = Args.notBlank(name, "name");
      this.issuerName = issuerName;
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.entries = notEmpty(entries, "entries");
    }

    public String issuerName() {
      return issuerName;
    }

    public static KeyCertConf2 parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("entries");
      List<SingleKeyCert> entries = null;
      if (list != null) {
        entries = SingleKeyCert.parseList(list);
      }

      return new KeyCertConf2(json.getString("name"), json.getString("issuerName"),
          json.getString("p12Password"), entries);
    }

    public static List<KeyCertConf2> parseList(JsonList json) throws CodecException {
      List<KeyCertConf2> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class SingleKeyCert {

    private final String keyType;
    // C509, X509 (default)
    private final CertFormat certFormat;
    // TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;

    public SingleKeyCert(String keyType, CertFormat certFormat, String certType,
                         String subject, String validity) {
      this.keyType = Args.notBlank(keyType, "keyType");
      this.certFormat = certFormat == null ? CertFormat.X509 : certFormat;
      this.certType = certType;
      this.subject = Args.notBlank(subject, "subject");
      this.validity = Args.notBlank(validity, "validity");
      if ("CA".equalsIgnoreCase(certType)) {
        throw new IllegalArgumentException("certType CA is not allowed");
      }
    }

    public static SingleKeyCert parse(JsonMap json) throws CodecException {
      return new SingleKeyCert(json.getString("keyType"),
          json.getEnum("certFormat", CertFormat.class), json.getString("certType"),
          json.getString("subject"), json.getString("validity"));
    }

    public static List<SingleKeyCert> parseList(JsonList json) throws CodecException {
      List<SingleKeyCert> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class KeyStoreAndCert {
    private final byte[] keystoreBytes;

    private final CertChoice cert;

    public KeyStoreAndCert(byte[] keystoreBytes, CertChoice cert) {
      this.keystoreBytes = keystoreBytes;
      this.cert = cert;
    }
  }

  private static class SecretKeyEntry {

    // AES/128, AES/192, AES/256
    private final String keyType;
    private final String alias;

    public SecretKeyEntry(String keyType, String alias) {
      this.keyType = Args.notBlank(keyType, "keyType");
      this.alias = Args.notBlank(alias, "alias");
    }

    public String keyType() {
      return keyType;
    }

    public String alias() {
      return alias;
    }

    public static SecretKeyEntry parse(JsonMap json) throws CodecException {
      return new SecretKeyEntry(json.getString("keyType"), json.getString("alias"));
    }

    public static List<SecretKeyEntry> parseList(JsonList json) throws CodecException {
      List<SecretKeyEntry> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class SecretKeyConf {
    private final String name;
    private final String password;
    private final List<SecretKeyEntry> keys;

    public SecretKeyConf(String name, String password, List<SecretKeyEntry> keys) {
      this.name = Args.notBlank(name, "name");
      this.password = Args.notBlank(password, "p12Password");
      this.keys = Args.notEmpty(keys, "keys");
      if (keys.size() > 1) {
        List<String> aliases = new ArrayList<>(keys.size());
        for (SecretKeyEntry entry : keys) {
          String alias = entry.alias;
          if (aliases.contains(alias)) {
            throw new IllegalArgumentException("duplicated alias " + alias);
          }
          aliases.add(alias);
        }
      }

    }

    public static SecretKeyConf parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("keys");

      List<SecretKeyEntry> keys = null;
      if (list != null) {
        keys = SecretKeyEntry.parseList(list);
      }

      return new SecretKeyConf(json.getString("name"), json.getString("password"), keys);
    }

    public static List<SecretKeyConf> parseList(JsonList json) throws CodecException {
      List<SecretKeyConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

    public String name() {
      return name;
    }

    public String password() {
      return password;
    }

    public List<SecretKeyEntry> keys() {
      return keys;
    }

  }

  public static void main(String[] args) {
    boolean argsValid = args != null && args.length == 2;
    if (argsValid) {
      argsValid = StringUtil.isNotBlank(args[0]) && StringUtil.isNotBlank(args[1]);
    }

    if (!argsValid) {
      printUsage();
      return;
    }

    String confFile = args[0];
    String targetDir = args[1];
    try {
      generateKeyCerts(confFile, targetDir);
    } catch (Exception ex) {
      ex.printStackTrace();
      System.out.println("error: " + ex.getMessage());
    }
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("  java " + GenerateCerts.class.getName() + " <conf file> <target dir>");
  }

  private static CertChoice parseCert(File file)
      throws IOException, CertificateEncodingException {
    return parseCert(IoUtil.read(file));
  }

  private static CertChoice parseCert(byte[] bytes) throws CertificateEncodingException {
    bytes = X509Util.toDerEncoded(bytes);
    if (bytes[0] == 0x30) {
      return new CertChoice(X509Util.parseCert(bytes));
    } else {
      return new CertChoice(C509Util.parseCert(bytes));
    }
  }

  private static X509Cert[] toX509Certs(CertChoice[] certs) {
    for (CertChoice c : certs) {
      if (c.x509 == null) {
        throw new IllegalArgumentException("certs contains non-X509 certificate");
      }
    }

    X509Cert[] r = new X509Cert[certs.length];
    int index = 0;
    for (CertChoice c : certs) {
      r[index++] = c.x509;
    }
    return r;
  }

  private static C509Cert[] toC509Certs(CertChoice[] certs) {
    for (CertChoice c : certs) {
      if (c.c509 == null) {
        throw new IllegalArgumentException("certs contains non-C509 certificate");
      }
    }

    C509Cert[] r = new C509Cert[certs.length];
    int index = 0;
    for (CertChoice c : certs) {
      r[index++] = c.c509;
    }
    return r;
  }

  private static List<CertChoice> parseCerts(File certsFile)
      throws IOException, CertificateException {
    List<CertChoice> certs = new LinkedList<>();
    try (FileInputStream certsStream = new FileInputStream(certsFile);
        PemReader pemReader = new PemReader(
            new InputStreamReader(certsStream, StandardCharsets.UTF_8))) {
      PemObject pemObj;
      while ((pemObj = pemReader.readPemObject()) != null) {
        if (pemObj.getType().contains("CERTIFICATE")) {
          certs.add(parseCert(pemObj.getContent()));
        }
      }
    }
    return certs;
  }

  private static void generateKeyCerts(String confFile, String targetDirPath) throws Exception {
    File targetDir = new File(targetDirPath);
    if (targetDir.exists()) {
      if (!targetDir.isDirectory()) {
        throw new InvalidConfException("The path " + targetDirPath + " is not a directory.");
      }
    }

    JsonMap root = JsonParser.parseMap(Paths.get(confFile), true);
    Conf conf = Conf.parse(root);
    conf.validate();

    Map<String, CertChoice[]> nameCertMap = new HashMap<>();
    Map<String, KeyWithCert> caKeyAndCertPairMap = new HashMap<>();
    Set<String> namesOfGeneratedKeyCerts = new HashSet<>();

    if (conf.secretkeys != null) {
      File baseDir = new File(targetDir, "secretkeys");
      baseDir.mkdirs();

      for (SecretKeyConf skConf : conf.secretkeys) {
        char[] password = skConf.password.toCharArray();
        KeyStore ks = KeyUtil.loadKeyStore("JCEKS", null, null);
        for (SecretKeyEntry entry : skConf.keys()) {
          SecretKey key = generateSecretKey(entry.keyType);
          ks.setKeyEntry(entry.alias, key, password, null);
        }

        try (OutputStream out = new FileOutputStream(new File(baseDir, skConf.name + ".jceks"))) {
          ks.store(out, password);
        }
      }
    }

    for (KeyCertConf keyCertConf : conf.keycerts) {
      String name = keyCertConf.name;
      boolean isCA = "CA".equalsIgnoreCase(keyCertConf.certType);

      File baseDir = new File(targetDir, isCA ? "CA-" + name : name);
      if (baseDir.exists()) {
        CertChoice cert = parseCert(new File(baseDir, name + "-cert.pem"));
        nameCertMap.put(name, new CertChoice[]{cert});

        PrivateKeyInfo pkInfo = PrivateKeyInfo.fromEncoded(
            X509Util.toDerEncoded(IoUtil.read(new File(baseDir, name + "-key.pem"))));
        PrivateKey privateKey = KeyInfoUtil.getPrivateKey(pkInfo);

        if (isCA) {
          caKeyAndCertPairMap.put(name, new KeyWithCert(cert, privateKey));
        }

        System.out.println("keypair and certificate for " + name + " already exist, skipping it");
        continue;
      }

      System.out.println("Start generating key and certificates of " + name);
      KeySpec keySpec = KeySpec.ofKeySpec(keyCertConf.keyType);

      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams = new KeystoreGenerationParameters(password);
      String certType = keyCertConf.certType;
      Validity validity = Validity.getInstance(keyCertConf.validity);
      KeyStoreAndCert keyStoreAndCert;
      KeyPair keyPair;

      if (keyCertConf.certFormat == CertFormat.C509) {
        C509KeyPairWithSubjectPublicKeyInfo keyPairInfo = KeyUtil.generateC509KeyPair2(keySpec);
        C509SubjectPublicKey subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
        keyPair = keyPairInfo.keypair();

        C509Name subject = new C509Name(keyCertConf.subject);

        if (keyCertConf.issuerName == null) {
          Signer signer = KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic());

          keyStoreAndCert = generateC509SelfSignedCertificate(certType,
              signer.contentSigner(), keyPair.getPrivate(), subjectPublicKeyInfo,
              genParams, subject, validity);
        } else {
          KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName);
          if (caKeyCertPair == null) {
            throw new InvalidConfException("unknown CA " + keyCertConf.issuerName);
          }

          Signer signer = KeyUtil.getSigner(caKeyCertPair.key(), caKeyCertPair.cert().publicKey());
          keyStoreAndCert = generateC509Certificate(certType,
              signer.contentSigner(), caKeyCertPair.cert().c509, keyPair.getPrivate(),
              subjectPublicKeyInfo, genParams, subject, validity);
        }
      } else {
        X509KeyPairWithSubjectPublicKeyInfo keyPairInfo = KeyUtil.generateX509KeyPair2(keySpec);
        SubjectPublicKeyInfo subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
        keyPair = keyPairInfo.keypair();

        X500Name subject = new X500Name(keyCertConf.subject);

        if (keyCertConf.issuerName == null) {
          Signer signer = KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic());

          keyStoreAndCert = generateX509SelfSignedCertificate(certType,
              signer.contentSigner(), keyPair.getPrivate(), subjectPublicKeyInfo,
              genParams, subject, validity);
        } else {
          KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName);
          if (caKeyCertPair == null) {
            throw new InvalidConfException("unknown CA " + keyCertConf.issuerName);
          }

          Signer signer = KeyUtil.getSigner(caKeyCertPair.key(), caKeyCertPair.cert().publicKey());
          keyStoreAndCert = generateX509Certificate(certType,
              signer.contentSigner(), caKeyCertPair.cert().x509, keyPair.getPrivate(),
              subjectPublicKeyInfo, genParams, subject, validity);
        }
      }

      CertChoice cert = keyStoreAndCert.cert;
      nameCertMap.put(name, new CertChoice[]{cert});

      if (isCA) {
        caKeyAndCertPairMap.put(name, new KeyWithCert(cert, keyPair.getPrivate()));
      }

      byte[] certBytes = cert.getEncoded();
      IoUtil.save(new File(baseDir, name + "-cert.pem"),
          PemEncoder.encode(certBytes, PemEncoder.PemLabel.CERTIFICATE));

      IoUtil.save(new File(baseDir, name + ".p12"), keyStoreAndCert.keystoreBytes);
      byte[] keyBytes = keyPair.getPrivate().getEncoded();
      IoUtil.save(new File(baseDir, name + "-key.pem"),
          PemEncoder.encode(keyBytes, PemEncoder.PemLabel.PRIVATE_KEY));

      System.out.println("Finished generating key and certificates of " + name);
      namesOfGeneratedKeyCerts.add(name);
    }

    for (KeyCertConf2 keyCertConf : conf.keycerts2) {
      String name = keyCertConf.name;

      File baseDir = new File(targetDir, name);
      if (baseDir.exists()) {
        List<CertChoice> certs0 = parseCerts(new File(baseDir, name + "-certs.pem"));

        List<PrivateKey> keys = new LinkedList<>();
        try (PemReader pemReader = new PemReader(new FileReader(
            new File(baseDir, name + "-keys.pem")))) {
          while (true) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
              break;
            }

            PrivateKeyInfo pkInfo = PrivateKeyInfo.fromEncoded(pemObject.getContent());
            keys.add(KeyInfoUtil.getPrivateKey(pkInfo));
          }
        }

        if (certs0.size() != keys.size()) {
          throw new InvalidConfException("number of existing certificate (" + certs0.size() +
              ") != number of existing keys (" + keys.size() + ") for " + name);
        }

        nameCertMap.put(name, certs0.toArray(new CertChoice[0]));

        System.out.println("keypair and certificate for " + name + " already exist, skipping it");
        continue;
      }

      System.out.println("Start generating key and certificates of " + name);
      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams = new KeystoreGenerationParameters(password);

      int size = keyCertConf.entries.size();
      CertChoice[] thisCerts = new CertChoice[size];
      PrivateKey[] thisKeys = new PrivateKey[size];

      int index = 0;
      for (SingleKeyCert entry : keyCertConf.entries) {
        KeySpec keySpec = KeySpec.ofKeySpec(entry.keyType);

        KeyStoreAndCert keyStoreAndCert;
        if (entry.certFormat == CertFormat.C509) {
          C509KeyPairWithSubjectPublicKeyInfo keyPairInfo = KeyUtil.generateC509KeyPair2(keySpec);

          C509SubjectPublicKey subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
          KeyPair keyPair = keyPairInfo.keypair();

          Validity validity = Validity.getInstance(entry.validity);
          C509Name subject = new C509Name(entry.subject);
          String certType = entry.certType;

          if (keyCertConf.issuerName() == null) {
            Signer signer = KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic(), true);

            keyStoreAndCert = generateC509SelfSignedCertificate(certType,
                signer.contentSigner(), keyPair.getPrivate(), subjectPublicKeyInfo,
                genParams, subject, validity);
          } else {
            KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName());
            if (caKeyCertPair == null) {
              throw new InvalidConfException("unknown CA " + keyCertConf.issuerName());
            }
            Signer signer = KeyUtil.getSigner(caKeyCertPair.key(), caKeyCertPair.cert().publicKey());
            keyStoreAndCert = generateC509Certificate(certType, signer.contentSigner(),
                caKeyCertPair.cert().c509, keyPair.getPrivate(), subjectPublicKeyInfo, genParams,
                subject, validity);
          }

          CertChoice cert = keyStoreAndCert.cert;
          thisCerts[index] = cert;
          thisKeys[index] = keyPairInfo.keypair().getPrivate();
        } else {
          X509KeyPairWithSubjectPublicKeyInfo keyPairInfo = KeyUtil.generateX509KeyPair2(keySpec);

          SubjectPublicKeyInfo subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
          KeyPair keyPair = keyPairInfo.keypair();

          Validity validity = Validity.getInstance(entry.validity);
          X500Name subject = new X500Name(entry.subject);
          String certType = entry.certType;


          if (keyCertConf.issuerName() == null) {
            Signer signer = KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic(), true);

            keyStoreAndCert = generateX509SelfSignedCertificate(certType,
                signer.contentSigner(), keyPair.getPrivate(), subjectPublicKeyInfo,
                genParams, subject, validity);
          } else {
            KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName());
            if (caKeyCertPair == null) {
              throw new InvalidConfException("unknown CA " + keyCertConf.issuerName());
            }
            Signer signer = KeyUtil.getSigner(caKeyCertPair.key(), caKeyCertPair.cert().publicKey());
            keyStoreAndCert = generateX509Certificate(certType, signer.contentSigner(),
                caKeyCertPair.cert().x509, keyPair.getPrivate(), subjectPublicKeyInfo, genParams,
                subject, validity);
          }

          CertChoice cert = keyStoreAndCert.cert;
          thisCerts[index] = cert;
          thisKeys[index] = keyPairInfo.keypair().getPrivate();
        }
        index++;
      }

      nameCertMap.put(name, thisCerts);

      String pemStr;
      if (thisCerts[0].x509 != null) {
        pemStr = X509Util.encodePemCertificates(toX509Certs(thisCerts));
      } else {
        pemStr = C509Util.encodePemCertificates(toC509Certs(thisCerts));
      }
      assert pemStr != null;

      IoUtil.save(new File(baseDir, name + "-certs.pem"),
          pemStr.getBytes(StandardCharsets.UTF_8));

      Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);

      for (int i = 0; i < size; i++) {
        String alias = name + "-" + (i + 1);
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.fromEncoded(thisKeys[i].getEncoded());
        if (thisCerts[i].x509 != null) {
          ks.setKeyEntry(alias, privateKeyInfo, thisCerts[i].x509.getCert());
        } else {
          ks.setC509KeyEntry(alias, privateKeyInfo, thisCerts[i].c509.getCert());
        }
      }

      try (OutputStream keystoreOs = new FileOutputStream(new File(baseDir, name + ".p12"))) {
        ks.store(keystoreOs, password);
      }

      ByteArrayOutputStream pemKeyStreams = new ByteArrayOutputStream();
      for (int i = 0; i < size; i++) {
        pemKeyStreams.write(PemEncoder.encode(thisKeys[i].getEncoded(),
            PemEncoder.PemLabel.PRIVATE_KEY));
      }

      IoUtil.save(new File(baseDir, name + "-keys.pem"), pemKeyStreams.toByteArray());

      System.out.println("Finished generating key and certificates of " + name);
      namesOfGeneratedKeyCerts.add(name);
    }

    if (conf.certstores != null) {
      File baseDir = new File(targetDir, "certstore");
      baseDir.mkdirs();

      for (CertStore certstore : conf.certstores) {
        String name = certstore.name;
        // check whether any certificate is newly generated.
        boolean containsNewGeneratedCerts = false;
        for (String certName : certstore.keyCertNames) {
          if (namesOfGeneratedKeyCerts.contains(certName)) {
            containsNewGeneratedCerts = true;
            break;
          }
        }

        if (!containsNewGeneratedCerts) {
          System.out.println("No change to certificate keystore " + name + ", skipping it");
          continue;
        }

        Pkcs12KeyStore certP12Ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
        certP12Ks.load((byte[]) null, null);

        List<CertChoice> certs = new ArrayList<>(certstore.keyCertNames.size());

        for (String certName : certstore.keyCertNames) {
          CertChoice[] certsList = nameCertMap.get(certName);
          certs.addAll(Arrays.asList(certsList));

          if (certsList[0].x509 != null) {
            certP12Ks.setCertificateEntry(certName, certsList[0].x509.getCert());
            if (certsList.length > 1) {
              for (int i = 1; i < certsList.length; i++) {
                certP12Ks.setCertificateEntry(certName + "-" + i, certsList[i].x509.getCert());
              }
            }
          } else {
            certP12Ks.setC509CertificateEntry(certName, certsList[0].c509.getCert());
            if (certsList.length > 1) {
              for (int i = 1; i < certsList.length; i++) {
                certP12Ks.setC509CertificateEntry(certName + "-" + i, certsList[i].c509.getCert());
              }
            }
          }
        }

        try (OutputStream out = new FileOutputStream(new File(baseDir, name + "-certstore.p12"))) {
          certP12Ks.store(out, certstore.p12Password.toCharArray());
        }

        String pemStr;
        if (certs.get(0).x509 != null) {
          pemStr = X509Util.encodePemCertificates(toX509Certs(certs.toArray(new CertChoice[0])));
        } else {
          pemStr = C509Util.encodePemCertificates(toC509Certs(certs.toArray(new CertChoice[0])));
        }
        assert pemStr != null;

        IoUtil.save(new File(baseDir, name + "-certstore.pem"),
            pemStr.getBytes(StandardCharsets.UTF_8));
      }
    }

  }

  private static KeyStoreAndCert generateX509SelfSignedCertificate(
      String certType, ContentSigner signer, PrivateKey privateKey,
      SubjectPublicKeyInfo subjectPublicKeyInfo, KeystoreGenerationParameters params,
      X500Name subject, Validity validity) throws Exception {
    return generateX509Certificate(certType, signer, null, privateKey,
        subjectPublicKeyInfo, params, subject, validity);
  }

  private static KeyStoreAndCert generateC509SelfSignedCertificate(
      String certType, ContentSigner signer, PrivateKey privateKey,
      C509SubjectPublicKey subjectPublicKeyInfo, KeystoreGenerationParameters params,
      C509Name subject, Validity validity) throws Exception {
    return generateC509Certificate(certType, signer, null, privateKey,
        subjectPublicKeyInfo, params, subject, validity);
  }

  private static KeyStoreAndCert generateX509Certificate(
      String certType, ContentSigner signer, X509Cert issuerCert, PrivateKey privateKey,
      SubjectPublicKeyInfo subjectPublicKeyInfo, KeystoreGenerationParameters params,
      X500Name subject, Validity validity) throws Exception {
    certType = certType.toUpperCase(Locale.ROOT);
    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    Instant notAfter = validity.add(notBefore);

    BigInteger serialNumber;
    X500Name issuer;
    if (issuerCert == null) {
      serialNumber = BigInteger.ONE;
      issuer = subject;
    } else {
      if (notAfter.isAfter(issuerCert.notAfter())) {
        notAfter = issuerCert.notAfter();
      }
      serialNumber = new BigInteger(72, RandomUtil.random());
      issuer = issuerCert.subject();
    }

    // Generate keystore
    Certificate.V3CertBuilder certGenerator = new Certificate.V3CertBuilder(
        issuer, serialNumber, notBefore, notAfter, subject, subjectPublicKeyInfo);

    if (issuerCert != null) {
      certGenerator.addExtension(Extension.ofAuthorityKeyIdentifier(false,
          new AuthorityKeyIdentifier(issuerCert.subjectKeyId())));
    }

    byte[] encodedSpki = subjectPublicKeyInfo.subjectPublicKey();
    byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
    certGenerator.addExtension(Extension.ofSubjectKeyIdentifier(false,
        new SubjectKeyIdentifier(skiValue)));

    boolean isCA = "CA".equalsIgnoreCase(certType);
    BasicConstraints basicConstraints = isCA ? new BasicConstraints(0)
        : new BasicConstraints(false);
    certGenerator.addExtension(Extension.ofBasicConstraints(true, basicConstraints));

    KeyUsage keyUsage = isCA
        ? new KeyUsage(KeyUsage.keyCertSign, KeyUsage.cRLSign)
        : new KeyUsage(KeyUsage.digitalSignature);
    certGenerator.addExtension(Extension.ofKeyUsage(true, keyUsage));

    if ("TLS-SERVER".equals(certType) || "TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
      List<Asn1Oid> purposeIds = new LinkedList<>();
      if ("TLS-SERVER".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeOIDs.id_kp_serverAuth);
        String commonName = X509Util.getCommonName(subject);
        if (commonName == null) {
          throw new InvalidConfException("common name of a TLS certificate must not be null");
        }

        GeneralName generalName = IPAddressUtil.isValid(commonName)
            ? GeneralName.ofTagName(GeneralName.tag_iPAddress, commonName)
            : GeneralName.ofTagName(GeneralName.tag_dNSName,   commonName);

        certGenerator.addExtension(Extension.ofSubjectAlternativeName(
            false, new GeneralNames(new GeneralName[]{generalName})));
      }

      if ("TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeOIDs.id_kp_clientAuth);
      }

      certGenerator.addExtension(Extension.ofExtendedKeyUsage(false,
          new ExtendedKeyUsage(purposeIds)));
    }

    Certificate cert = certGenerator.build(signer);

    Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
    ks.setKeyEntry("main", PrivateKeyInfo.fromPrivateKey(privateKey), cert);

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    return new KeyStoreAndCert(ksStream.toByteArray(), new CertChoice(new X509Cert(cert)));
  }


  private static KeyStoreAndCert generateC509Certificate(
      String certType, ContentSigner signer, C509Cert issuerCert, PrivateKey privateKey,
      C509SubjectPublicKey subjectPublicKeyInfo, KeystoreGenerationParameters params,
      C509Name subject, Validity validity) throws Exception {
    certType = certType.toUpperCase(Locale.ROOT);
    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
    Instant notAfter = validity.add(notBefore);

    BigInteger serialNumber;
    C509Name issuer;
    if (issuerCert == null) {
      serialNumber = BigInteger.ONE;
      issuer = subject;
    } else {
      if (notAfter.isAfter(issuerCert.notAfter())) {
        notAfter = issuerCert.notAfter();
      }
      serialNumber = new BigInteger(72, RandomUtil.random());
      issuer = issuerCert.subject();
    }

    // Generate keystore
    C509CertificateBuilder certGenerator = C509CertificateBuilder.of(subject, subjectPublicKeyInfo)
        .validity(notBefore, notAfter).serialNumber(serialNumber);
    if (issuerCert != null) {
      certGenerator.issuedBy(issuerCert.getCert());
    }

    boolean isCA = "CA".equalsIgnoreCase(certType);
    C509BasicConstraints basicConstraints = isCA ? C509BasicConstraints.ca(0)
        : C509BasicConstraints.END_ENTITY;
    certGenerator.extension(ConstExtensionId.basicConstraints, true, basicConstraints);

    C509KeyUsage keyUsage = isCA
        ? C509KeyUsage.of(C509KeyUsage.KEY_CERT_SIGN, C509KeyUsage.CRL_SIGN)
        : C509KeyUsage.of(C509KeyUsage.DIGITAL_SIGNATURE);
    certGenerator.extension(ConstExtensionId.keyUsage, true, keyUsage);

    if ("TLS-SERVER".equals(certType) || "TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
      List<Long> purposeIds = new LinkedList<>();
      if ("TLS-SERVER".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(ConstExtendedKeyUsage.serverAuth);
        String commonName = C509Util.getCommonName(subject);
        if (commonName == null) {
          throw new InvalidConfException("common name of a TLS certificate must not be null");
        }

        C509GeneralName generalName = IPAddressUtil.isValid(commonName)
            ? C509GeneralName.ip(commonName) : C509GeneralName.dns(commonName);

        certGenerator.extension(ConstExtensionId.subjectAltName,
            false, new C509AltName(C509GeneralNames.of(generalName)));
      }

      if ("TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(ConstExtendedKeyUsage.clientAuth);
      }

      certGenerator.extension(ConstExtensionId.extKeyUsage, false,
          new C509ExtKeyUsageSyntax(purposeIds));
    }

    C509Certificate cert = certGenerator.build(signer);

    Pkcs12KeyStore ks = KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
    ks.setC509KeyEntry("main", PrivateKeyInfo.fromPrivateKey(privateKey), cert);

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    return new KeyStoreAndCert(ksStream.toByteArray(), new CertChoice(new C509Cert(cert)));
  }

  private static SecretKey generateSecretKey(String keyType) throws Exception {
    keyType = keyType.toUpperCase(Locale.ROOT);
    if (keyType.startsWith("AES")) {
      int keySize = Integer.parseUnsignedInt(keyType, "AES/".length(), keyType.length(), 10);
      if (keySize != 128 && keySize != 192 && keySize != 256) {
        throw new InvalidConfException("invalid keyType '" + keyType + "'");
      }

      byte[] keyValue = RandomUtil.nextBytes(keySize / 8);
      return new SecretKeySpec(keyValue, "AES");
    } else {
      throw new InvalidConfException("invalid keyType '" + keyType + "'");
    }
  }

  private static class KeyWithCert {

    private final CertChoice cert;

    private final PrivateKey key;

    public KeyWithCert(CertChoice cert, PrivateKey key) {
      this.key = key;
      this.cert = cert;
    }

    public CertChoice cert() {
      return cert;
    }

    public PrivateKey key() {
      return key;
    }
  }

}
