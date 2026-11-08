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
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.KeyPurposeOIDs;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.ipadress.IPAddressUtil;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.pem.PemObject;
import org.xipki.crypto.core.pem.PemReader;
import org.xipki.util.misc.PemEncoder;
import org.xipki.pkix.pkcs12.KeyPairWithSubjectPublicKeyInfo;
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
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
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
    // CA, TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;
    private final String p12Password;

    public KeyCertConf(String name, String issuerName, String keyType,
                      String certType, String subject, String validity, String p12Password) {
      this.name = Args.notBlank(name, "name");
      this.keyType = Args.notBlank(keyType, "keyType");
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
          json.getString("keyType"), json.getString("certType"),
          json.getString("subject"), json.getString("validity"), json.getString("p12Password"));
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
    // TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;

    public SingleKeyCert(String keyType, String certType, String subject, String validity) {
      this.keyType = Args.notBlank(keyType, "keyType");
      this.certType = certType;
      this.subject = Args.notBlank(subject, "subject");
      this.validity = Args.notBlank(validity, "validity");
      if ("CA".equalsIgnoreCase(certType)) {
        throw new IllegalArgumentException("certType CA is not allowed");
      }
    }

    public static SingleKeyCert parse(JsonMap json) throws CodecException {
      return new SingleKeyCert(json.getString("keyType"), json.getString("certType"),
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

    private final X509Cert cert;

    public KeyStoreAndCert(byte[] keystoreBytes, X509Cert cert) {
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

    Map<String, X509Cert[]>  nameCertMap = new HashMap<>();
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
        X509Cert cert = X509Util.parseCert(new File(baseDir, name + "-cert.pem"));
        nameCertMap.put(name, new X509Cert[]{cert});

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

      KeyPairWithSubjectPublicKeyInfo keyPairInfo = X509KeyUtil.generateKeyPair2(keySpec);
      SubjectPublicKeyInfo subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
      KeyPair keyPair = keyPairInfo.keypair();

      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams = new KeystoreGenerationParameters(password);

      Validity validity = Validity.getInstance(keyCertConf.validity);
      X500Name subject = new X500Name(keyCertConf.subject);
      String certType = keyCertConf.certType;

      KeyStoreAndCert keyStoreAndCert;

      if (keyCertConf.issuerName == null) {
        Signer signer = X509KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic());

        keyStoreAndCert = generateSelfSignedCertificate(certType, signer.x509Signer(),
            keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
      } else {
        KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName);
        if (caKeyCertPair == null) {
          throw new InvalidConfException("unknown CA " + keyCertConf.issuerName);
        }
        Signer signer =
            X509KeyUtil.getSigner(caKeyCertPair.key(), caKeyCertPair.cert().publicKey());
        keyStoreAndCert = generateCertificate(certType, signer.x509Signer(), caKeyCertPair.cert(),
            keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
      }

      X509Cert cert = keyStoreAndCert.cert;
      nameCertMap.put(name, new X509Cert[]{cert});

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
        List<X509Cert> certs0 = X509Util.parseCerts(new File(baseDir, name + "-certs.pem"));

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

        nameCertMap.put(name, certs0.toArray(new X509Cert[0]));

        System.out.println("keypair and certificate for " + name + " already exist, skipping it");
        continue;
      }

      System.out.println("Start generating key and certificates of " + name);
      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams = new KeystoreGenerationParameters(password);

      int size = keyCertConf.entries.size();
      X509Cert[] thisCerts = new X509Cert[size];
      PrivateKey[] thisKeys = new PrivateKey[size];

      int index = 0;
      for (SingleKeyCert entry : keyCertConf.entries) {
        KeySpec keySpec = KeySpec.ofKeySpec(entry.keyType);

        KeyPairWithSubjectPublicKeyInfo keyPairInfo = X509KeyUtil.generateKeyPair2(keySpec);

        SubjectPublicKeyInfo subjectPublicKeyInfo = keyPairInfo.subjectPublicKeyInfo();
        KeyPair keyPair = keyPairInfo.keypair();

        Validity validity = Validity.getInstance(entry.validity);
        X500Name subject = new X500Name(entry.subject);
        String certType = entry.certType;

        KeyStoreAndCert keyStoreAndCert;

        if (keyCertConf.issuerName() == null) {
          Signer signer = X509KeyUtil.getSigner(keyPair.getPrivate(), keyPair.getPublic(), true);

          keyStoreAndCert = generateSelfSignedCertificate(certType, signer.x509Signer(),
              keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
        } else {
          KeyWithCert caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.issuerName());
          if (caKeyCertPair == null) {
            throw new InvalidConfException("unknown CA " + keyCertConf.issuerName());
          }
          Signer signer = X509KeyUtil.getSigner(caKeyCertPair.key(),
              caKeyCertPair.cert().publicKey());
          keyStoreAndCert = generateCertificate(certType, signer.x509Signer(), caKeyCertPair.cert(),
              keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
        }

        X509Cert cert = keyStoreAndCert.cert;
        thisCerts[index] = cert;
        thisKeys[index] = keyPairInfo.keypair().getPrivate();
        index++;
      }

      nameCertMap.put(name, thisCerts);

      IoUtil.save(new File(baseDir, name + "-certs.pem"),
          Objects.requireNonNull(X509Util.encodeCertificates(thisCerts))
              .getBytes(StandardCharsets.UTF_8));

      Pkcs12KeyStore ks = X509KeyUtil.loadPKCS12KeyStore((byte[]) null, null);

      for (int i = 0; i < size; i++) {
        ks.setKeyEntry(name + "-" + (i + 1),
            PrivateKeyInfo.fromEncoded(thisKeys[i].getEncoded()), thisCerts[i].getCert());
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

        Pkcs12KeyStore certP12Ks = X509KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
        certP12Ks.load((byte[]) null, null);

        List<X509Cert> certs = new ArrayList<>(certstore.keyCertNames.size());

        for (String certName : certstore.keyCertNames) {
          X509Cert[] certs0 = nameCertMap.get(certName);
          certs.addAll(Arrays.asList(certs0));

          certP12Ks.setCertificateEntry(certName, certs0[0].getCert());
          if (certs0.length > 1) {
            for (int i = 1; i < certs0.length; i++) {
              certP12Ks.setCertificateEntry(certName + "-" + i, certs0[i].getCert());
            }
          }
        }

        try (OutputStream out = new FileOutputStream(new File(baseDir, name + "-certstore.p12"))) {
          certP12Ks.store(out, certstore.p12Password.toCharArray());
        }

        IoUtil.save(new File(baseDir, name + "-certstore.pem"),
            X509Util.encodeCertificates(certs.toArray(new X509Cert[0]))
                .getBytes(StandardCharsets.UTF_8));
      }
    }

  }

  private static KeyStoreAndCert generateSelfSignedCertificate(
      String certType, ContentSigner signer, PrivateKey privateKey,
      SubjectPublicKeyInfo subjectPublicKeyInfo, KeystoreGenerationParameters params,
      X500Name subject, Validity validity) throws Exception {
    return generateCertificate(certType, signer, null, privateKey,
        subjectPublicKeyInfo, params, subject, validity);
  }

  private static KeyStoreAndCert generateCertificate(
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

    KeyWithCert identity = new KeyWithCert(new X509Cert(certGenerator.build(signer)), privateKey);

    Pkcs12KeyStore ks = X509KeyUtil.loadPKCS12KeyStore((byte[]) null, null);
    ks.setKeyEntry("main", PrivateKeyInfo.fromPrivateKey(privateKey), identity.cert().getCert());

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.password());
    } finally {
      ksStream.flush();
    }

    return new KeyStoreAndCert(ksStream.toByteArray(), identity.cert());
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

    private final X509Cert cert;

    private final PrivateKey key;

    public KeyWithCert(X509Cert cert, PrivateKey key) {
      this.key = key;
      this.cert = cert;
    }

    public X509Cert cert() {
      return cert;
    }

    public PrivateKey key() {
      return key;
    }
  }
}
