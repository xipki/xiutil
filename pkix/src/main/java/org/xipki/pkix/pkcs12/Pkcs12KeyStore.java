// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.asn1.cms.ContentInfo;
import org.xipki.asn1.cms.EncryptedContentInfo;
import org.xipki.asn1.cms.EncryptedData;
import org.xipki.asn1.pkcs12.AuthenticatedSafe;
import org.xipki.asn1.pkcs12.CertBag;
import org.xipki.asn1.pkcs12.MacData;
import org.xipki.asn1.pkcs12.Pfx;
import org.xipki.asn1.pkcs12.SafeBag;
import org.xipki.asn1.pkcs12.SafeContents;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.Certificate;
import org.xipki.asn1.x509.Extension;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.ext.C509ExtKeyUsageSyntax;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.x509.id.XipkiOIDs;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.util.XiArrays;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.PBES2Parameters;
import org.xipki.codec.x509.PBKDF2Params;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.x509.id.ExtensionOIDs;
import org.xipki.codec.x509.id.KeyPurposeOIDs;
import org.xipki.codec.x509.id.MiscOIDs;
import org.xipki.codec.x509.id.NistOIDs;
import org.xipki.codec.x509.id.NttOIDs;
import org.xipki.codec.x509.id.OiwOIDs;
import org.xipki.codec.x509.id.PkcsOIDs;
import org.xipki.codec.x509.EncryptedPrivateKeyInfo;
import org.xipki.codec.x509.DigestInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.IoUtil;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * PKCS#12 keystore (RFC 7292) with key entries (private key and certificate chain) and
 * trusted-certificate entries.
 * <p>
 * Reading supports the PKCS#12 PBE schemes and PBES2 for keys and certificates, and the
 * PKCS#12 MAC and PBMAC1 (see {@link Pkcs12Pbe}). Writing uses, as the JDK and OpenSSL 3.x by
 * default, PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC for the keys and the certificates,
 * and the PKCS#12 MAC with HMAC-SHA256 (not PBMAC1, which the JDK cannot read). A key without
 * certificate is kept, and is written without certificate bag.
 *
 * @author Lijun Liao (xipki)
 */
public class Pkcs12KeyStore {

  /**
   * Byte array as map key.
   */
  private static final class Bytes {

    private final byte[] value;

    private final int hash;

    private Bytes(byte[] value) {
      this.value = value;
      this.hash = Arrays.hashCode(value);
    }

    @Override
    public int hashCode() {
      return hash;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }

      return o instanceof Bytes && Arrays.equals(value, ((Bytes) o).value);
    }

  }

  private static final class CertName {

    private final X500Name x509Name;

    private final C509Name c509Name;

    CertName(X500Name x509Name) {
      this.x509Name = x509Name;
      this.c509Name = null;
    }

    CertName(C509Name c509Name) {
      this.x509Name = null;
      this.c509Name = c509Name; // c509Name may be null for self-issued cert
    }

    @Override
    public int hashCode() {
      return x509Name != null ? x509Name.hashCode()
          : (c509Name != null) ? c509Name.hashCode() : 1;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }

      if (!(obj instanceof CertName)) {
        return false;
      }

      CertName b = (CertName) obj;
      return Objects.equals(x509Name, b.x509Name)
          && Objects.equals(c509Name, b.c509Name);
    }
  }

  private static final class Cert {

    private final Asn1Oid type;

    private final Certificate x509cert;

    private final C509Certificate c509cert;

    private final CertName issuer;

    private final CertName subject;

    public Cert(Certificate x509cert) {
      this.x509cert = Args.notNull(x509cert, "x509cert");
      this.c509cert = null;
      this.type = PkcsOIDs.x509Certificate;

      this.issuer = new CertName(x509cert.getIssuer());
      this.subject = new CertName(x509cert.getSubject());
    }

    public Cert(C509Certificate c509cert) {
      this.x509cert = null;
      this.c509cert = Args.notNull(c509cert, "c509cert");
      this.type = XipkiOIDs.id_xipki_certtype_c509cert;

      this.issuer = new CertName(c509cert.body().issuer());
      this.subject = new CertName(c509cert.body().subject());
    }

    byte[] subjectKeyId() {
      if (x509cert != null) {
        return sha1(x509cert.getSubjectPublicKeyInfo().subjectPublicKey());
      } else {
        return sha256_20(c509cert.subjectPublicKey().getEncoded());
      }
    }

    byte[] authorityKeyId() {
      if (x509cert != null) {
        Extension extn = x509cert.getExtension(ExtensionOIDs.authorityKeyIdentifier);
        return extn == null ? null : extn.getAuthorityKeyIdentifier().keyIdentifier();
      } else {
        return c509cert.extensions().authorityKeyId();
      }
    }

    public byte[] getEncoded() {
      if (x509cert != null) {
        return x509cert.getEncoded();
      } else {
        return c509cert.getEncoded();
      }
    }

  }

  /**
   * A certificate with the values computed only once.
   */
  private static final class CertInfo {

    private final Cert cert;

    private final byte[] encoded;

    /**
     * SHA-1 of the subjectPublicKey: the key of the certificate pool, and the localKeyId.
     */
    private final Bytes ski;

    private Bytes aki;

    private boolean akiResolved;

    private CertInfo(Cert cert, byte[] encoded) {
      this.cert = cert;
      this.encoded = encoded;
      this.ski = new Bytes(this.cert.subjectKeyId());
    }

    private static CertInfo of(Cert cert) {
      return new CertInfo(cert, cert.getEncoded());
    }

    /**
     * keyIdentifier of the AuthorityKeyIdentifier extension, or null.
     */
    private Bytes aki() {
      if (!akiResolved) {
        byte[] keyId = cert.authorityKeyId();
        aki = (keyId == null) ? null : new Bytes(keyId);
        akiResolved = true;
      }
      return aki;
    }

  }

  /**
   * A key entry (key != null) or a trusted-certificate entry (key == null).
   */
  private static final class Entry {

    private final PrivateKeyInfo key;

    /**
     * The certificate of the key, or the trusted certificate. Null for a key without certificate.
     */
    private final CertInfo cert;

    /**
     * localKeyId of a key without certificate, written as it was read. Null if absent.
     */
    private final byte[] localKeyId;

    private Entry(PrivateKeyInfo key, CertInfo cert, byte[] localKeyId) {
      this.key = key;
      this.cert = cert;
      this.localKeyId = localKeyId;
    }

  }

  /**
   * A bag of the file with its friendlyName and localKeyId.
   */
  private static final class Bag<T> {

    private final T value;

    private final String friendlyName;

    private final byte[] localKeyId;

    private Bag(T value, Attribute.Set0 attrs) throws CodecException {
      this.value = value;
      Attribute attr = (attrs == null) ? null
          : attrs.getOnlyAttribute(PkcsOIDs.pkcs9_at_friendlyName);
      this.friendlyName = (attr == null) ? null : attr.friendlyName();
      attr = (attrs == null) ? null : attrs.getOnlyAttribute(PkcsOIDs.pkcs9_at_localKeyId);
      this.localKeyId = (attr == null) ? null : attr.localKeyId();
    }

  }

  /**
   * PBES2 encryption schemes: OID to {key size, transformation, key algorithm}. For the schemes
   * without transformation, the OID is used as transformation and key algorithm.
   */
  private static final Map<String, Object[]> PBES2_SCHEMES = new HashMap<>();

  private static final int SALT_SIZE = 20;

  /**
   * The iteration count used when writing a PKCS#12 file, for PBKDF2 and for the integrity MAC.
   * 600,000 is the OWASP figure for PBKDF2-HMAC-SHA256. Due to the problem in Windows, we use the
   * in Windows maximal allowed value 300,000.
   */
  private static final int DEFAULT_STORE_IT_COUNT = 300000;

  private static final int ITERATIONS = DEFAULT_STORE_IT_COUNT;

  private static final CryptoApi crypto = CryptoApiFactory.get();

  static {
    pbes2(16, "AES/CBC/PKCS5Padding", "AES", NistOIDs.id_aes128_CBC);
    pbes2(24, "AES/CBC/PKCS5Padding", "AES", NistOIDs.id_aes192_CBC);
    pbes2(32, "AES/CBC/PKCS5Padding", "AES", NistOIDs.id_aes256_CBC);
    pbes2(24, "DESede/CBC/PKCS5Padding", "DESede", PkcsOIDs.des_EDE3_CBC);

    pbes2(5, null, null, PkcsOIDs.pbeWithSHAAnd40BitRC2_CBC);
    pbes2(8, null, null, OiwOIDs.desCBC);
    pbes2(16, null, null, MiscOIDs.cast5CBC, NistOIDs.id_aes128_GCM, NistOIDs.id_aes128_CCM,
        NistOIDs.id_aes128_CFB, NistOIDs.id_aes128_OFB, NistOIDs.id_aes128_wrap,
        NttOIDs.id_camellia128_cbc, NttOIDs.id_camellia128_wrap,
        PkcsOIDs.pbeWithSHAAnd2_KeyTripleDES_CBC, PkcsOIDs.pbeWithSHAAnd128BitRC2_CBC,
        PkcsOIDs.pbeWithSHAAnd128BitRC4);
    pbes2(20, null, null, PkcsOIDs.id_hmacWithSHA1);
    pbes2(24, null, null, PkcsOIDs.id_alg_CMS3DESwrap, NistOIDs.id_aes192_GCM,
        NistOIDs.id_aes192_CCM, NistOIDs.id_aes192_CFB, NistOIDs.id_aes192_OFB,
        NistOIDs.id_aes192_wrap, NttOIDs.id_camellia192_cbc, NttOIDs.id_camellia192_wrap,
        PkcsOIDs.pbeWithSHAAnd3_KeyTripleDES_CBC);
    pbes2(28, null, null, PkcsOIDs.id_hmacWithSHA224);
    pbes2(32, null, null, NistOIDs.id_aes256_GCM, NistOIDs.id_aes256_CCM,
        NistOIDs.id_aes256_CFB, NistOIDs.id_aes256_OFB, NistOIDs.id_aes256_wrap,
        PkcsOIDs.id_hmacWithSHA256, NttOIDs.id_camellia256_cbc, NttOIDs.id_camellia256_wrap);
    pbes2(48, null, null, PkcsOIDs.id_hmacWithSHA384);
    pbes2(64, null, null, PkcsOIDs.id_hmacWithSHA512);
  }

  private static void pbes2(int keySize, String transformation, String keyAlg, Asn1Oid... oids) {
    for (Asn1Oid oid : oids) {
      PBES2_SCHEMES.put(oid.getId(), new Object[]{keySize, transformation, keyAlg});
    }
  }

  /**
   * alias to entry, in insertion order.
   */
  private final Map<String, Entry> entries = new LinkedHashMap<>();

  /**
   * All certificates (of the key entries, their chains and the trusted certificates), by SKI.
   */
  private final Map<Bytes, CertInfo> certPool = new LinkedHashMap<>();

  /**
   * Certificates of the pool by subject, built when needed.
   */
  private Map<CertName, CertInfo> certsBySubject;

  public Pkcs12KeyStore() {
  }

  public static Pkcs12KeyStore fromStream(InputStream stream, char[] password) throws IOException {
    Pkcs12KeyStore r = new Pkcs12KeyStore();
    r.load(stream == null ? null : IoUtil.readAllBytes(stream), password);
    return r;
  }

  public static Pkcs12KeyStore fromEncoded(byte[] encoded, char[] password) throws IOException {
    Pkcs12KeyStore r = new Pkcs12KeyStore();
    r.load(encoded, password);
    return r;
  }

  // ---------------------------------------------------------------- entries

  public Set<String> aliases() {
    return new LinkedHashSet<>(entries.keySet());
  }

  public boolean isKeyEntry(String alias) {
    Entry entry = entries.get(alias);
    return entry != null && entry.key != null;
  }

  public PrivateKeyInfo getKey(String alias) {
    Entry entry = entries.get(Args.notNull(alias, "alias"));
    return (entry == null) ? null : entry.key;
  }

  /**
   * Returns the X.509 certificate of the key entry, or the trusted certificate.
   * @param alias the alias.
   * @return the certificate, or null if absent.
   */
  public Certificate getCertificate(String alias) {
    Entry entry = entries.get(Args.notNull(alias, "alias"));
    return (entry == null || entry.cert == null) ? null : entry.cert.cert.x509cert;
  }

  /**
   * Returns the C509 certificate of the key entry, or the trusted certificate.
   * @param alias the alias.
   * @return the certificate, or null if absent.
   */
  public C509Certificate getC509Certificate(String alias) {
    Entry entry = entries.get(Args.notNull(alias, "alias"));
    return (entry == null || entry.cert == null) ? null : entry.cert.cert.c509cert;
  }

  /**
   * Returns the X.509 certificate chain of a key entry, starting with its certificate.
   * @param alias the alias.
   * @return the chain, an empty list for a key without certificate, null if alias is not a key
   *         entry.
   */
  public List<Certificate> getCertificateChain(String alias) {
    Entry entry = entries.get(Args.notNull(alias, "alias"));
    if (entry == null || entry.key == null) {
      return null;
    }

    List<Certificate> chain = new ArrayList<>(3);
    for (CertInfo c : chain(entry)) {
      if (c.cert.x509cert != null) {
        chain.add(c.cert.x509cert);
      }
    }
    return chain.isEmpty() ? null : chain;
  }

  /**
   * Returns the C.509 certificate chain of a key entry, starting with its certificate.
   * @param alias the alias.
   * @return the chain, an empty list for a key without certificate, null if alias is not a key
   *         entry.
   */
  public List<C509Certificate> getC509CertificateChain(String alias) {
    Entry entry = entries.get(Args.notNull(alias, "alias"));
    if (entry == null || entry.key == null) {
      return null;
    }

    List<C509Certificate> chain = new ArrayList<>(3);
    for (CertInfo c : chain(entry)) {
      if (c.cert.c509cert != null) {
        chain.add(c.cert.c509cert);
      }
    }
    return chain.isEmpty() ? null : chain;
  }

  public void setCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    if (isKeyEntry(alias)) {
      throw new KeyStoreException("There is a key entry with the name " + alias + ".");
    }

    CertInfo certInfo = CertInfo.of(new Cert(cert));
    entries.put(alias, new Entry(null, certInfo, null));
    addToPool(certInfo);
  }

  public void setC509CertificateEntry(String alias, C509Certificate cert) throws KeyStoreException {
    if (isKeyEntry(alias)) {
      throw new KeyStoreException("There is a key entry with the name " + alias + ".");
    }

    CertInfo certInfo = CertInfo.of(new Cert(cert));
    entries.put(alias, new Entry(null, certInfo, null));
    addToPool(certInfo);
  }

  public void setKeyEntry(String alias, PrivateKeyInfo key, Certificate cert)
      throws KeyStoreException {
    setKeyEntry(alias, key, List.of(Args.notNull(cert, "cert")));
  }

  public void setC509KeyEntry(String alias, PrivateKeyInfo key, C509Certificate cert)
      throws KeyStoreException {
    setC509KeyEntry(alias, key, List.of(Args.notNull(cert, "cert")));
  }

  public void setKeyEntry(String alias, PrivateKeyInfo key, List<Certificate> chain)
      throws KeyStoreException {
    doSetKeyEntry(alias, key, chain, null);
  }

  public void setC509KeyEntry(String alias, PrivateKeyInfo key, List<C509Certificate> chain)
      throws KeyStoreException {
    doSetKeyEntry(alias, key, null, chain);
  }

  private void doSetKeyEntry(String alias, PrivateKeyInfo key,
                             List<Certificate> x509Chain, List<C509Certificate> c509Chain)
      throws KeyStoreException {
    if (key == null) {
      throw new KeyStoreException("PKCS12 does not support null key");
    }

    List<?> chain = x509Chain != null ? x509Chain : c509Chain;

    if (chain == null || chain.isEmpty()) {
      throw new KeyStoreException("chain may not be empty");
    }

    // List.contains(null) throws NullPointerException for immutable lists
    List<CertInfo> certInfos = new ArrayList<>(chain.size());
    for (Object c : chain) {
      if (c == null) {
        throw new KeyStoreException("chain may not contain null elements");
      } else if (c instanceof Certificate) {
        certInfos.add(CertInfo.of(new Cert((Certificate) c)));
      } else { // if (c instanceof C509Certificate) {
        certInfos.add(CertInfo.of(new Cert((C509Certificate) c)));
      }
    }

    Entry old = entries.get(alias);
    if (old != null && old.key != null && old.cert != null) {
      certPool.remove(old.cert.ski);
      certsBySubject = null;
    }

    for (CertInfo certInfo : certInfos) {
      addToPool(certInfo);
    }
    entries.put(alias, new Entry(key, certInfos.get(0), null));
  }

  private void addToPool(CertInfo cert) {
    certPool.put(cert.ski, cert);
    certsBySubject = null;
  }

  /**
   * The chain of a key entry: its certificate, then the issuers found in the pool by the
   * AuthorityKeyIdentifier, else by the issuer name. Ends at a self-signed certificate, a
   * missing issuer, or a loop.
   */
  private List<CertInfo> chain(Entry entry) {
    List<CertInfo> chain = new ArrayList<>(3);
    Set<Bytes> seen = new HashSet<>();

    CertInfo cert = entry.cert;
    while (cert != null && seen.add(new Bytes(cert.encoded))) {
      chain.add(cert);

      CertInfo issuer = (cert.aki() == null) ? null : certPool.get(cert.aki());
      if (issuer == null) {
        CertName issuerName = cert.cert.issuer;
        if (!issuerName.equals(cert.cert.subject)) {
          issuer = certsBySubject().get(issuerName);
        }
      }
      cert = issuer;
    }
    return chain;
  }

  private Map<CertName, CertInfo> certsBySubject() {
    if (certsBySubject == null) {
      certsBySubject = new HashMap<>();
      for (CertInfo c : certPool.values()) {
        certsBySubject.putIfAbsent(c.cert.subject, c);
      }
    }
    return certsBySubject;
  }

  // ---------------------------------------------------------------- load
  public void load(InputStream stream, char[] password) throws IOException {
    load(stream == null ? null : IoUtil.readAllBytes(stream), password);
  }

  /**
   * Loads the keystore.
   * @param encoded the encoded PKCS#12. Null to start with the current (initially empty) content.
   * @param password the password.
   * @throws IOException if the keystore cannot be read or the password is wrong.
   */
  public void load(byte[] encoded, char[] password) throws IOException {
    if (encoded == null) {
      return;
    }

    if (password == null) {
      throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
    }

    if (encoded.length == 0) {
      throw new EOFException("no data in keystore stream");
    }

    if (encoded[0] != 0x30) {
      throw new IOException("stream does not represent a PKCS12 key store");
    }

    try {
      load(Pfx.fromEncoded(encoded), password);
    } catch (CodecException e) {
      throw new IOException(e.getMessage(), e);
    }
  }

  private void load(Pfx pfx, char[] password) throws IOException, CodecException {
    ContentInfo authSafeInfo = pfx.getAuthSafe();
    boolean wrongZero = verifyMac(pfx.getMacData(), authSafeInfo, password);

    List<Bag<PrivateKeyInfo>> keyBags = new ArrayList<>();
    List<Bag<CertInfo>> certBags = new ArrayList<>();

    if (authSafeInfo.getContentType().equals(PkcsOIDs.data)) {
      AuthenticatedSafe authSafe = AuthenticatedSafe.fromEncoded(
          authSafeInfo.getContent().asOctetString().getOctets());

      for (ContentInfo ci : authSafe) {
        byte[] safeContents;
        if (ci.getContentType().equals(PkcsOIDs.data)) {
          safeContents = ci.getContent().asOctetString().getOctets();
        } else if (ci.getContentType().equals(PkcsOIDs.encryptedData)) {
          EncryptedContentInfo eci =
              EncryptedData.fromAsn1(ci.getContent().asSequence()).getEncryptedContentInfo();
          safeContents = crypt(Cipher.DECRYPT_MODE, eci.getContentEncryptionAlgorithm(),
              password, wrongZero, eci.encryptedContent());
        } else {
          continue;
        }

        readBags(SafeContents.fromEncoded(safeContents), password, wrongZero, keyBags, certBags);
      }
    }

    entries.clear();
    certPool.clear();
    certsBySubject = null;
    link(keyBags, certBags);
  }

  /**
   * Verifies the MAC.
   * @return whether the MAC uses the incorrect encoding of the empty password.
   */
  private static boolean verifyMac(MacData macData, ContentInfo authSafeInfo, char[] password)
      throws IOException {
    if (macData == null) {
      return false;
    }

    try {
      DigestInfo mac = macData.getMac();
      byte[] data = authSafeInfo.getContent().asOctetString().getOctets();
      byte[] expected = mac.digest();

      byte[] res = Pkcs12Pbe.calculatePbeMac(mac.getAlgorithmId(), macData.macSalt(),
          macData.iterations(), password, false, data);
      if (XiArrays.constantTimeAreEqual(res, expected)) {
        return false;
      }

      if (password.length == 0) {
        // try with the incorrect encoding of the empty password
        res = Pkcs12Pbe.calculatePbeMac(mac.getAlgorithmId(), macData.macSalt(),
            macData.iterations(), password, true, data);
        if (XiArrays.constantTimeAreEqual(res, expected)) {
          return true;
        }
      }
    } catch (GeneralSecurityException | CodecException e) {
      throw new IOException("error constructing MAC: " + e.getMessage(), e);
    }

    throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
  }

  private void readBags(SafeContents safeContents, char[] password, boolean wrongZero,
                        List<Bag<PrivateKeyInfo>> keyBags, List<Bag<CertInfo>> certBags)
      throws IOException, CodecException {
    for (SafeBag bag : safeContents) {
      Asn1Oid bagId = bag.getBagId();
      if (bagId.equals(PkcsOIDs.pkcs8ShroudedKeyBag)) {
        EncryptedPrivateKeyInfo eki = EncryptedPrivateKeyInfo.fromAsn1(
            bag.getBagValue().asSequence());
        byte[] key = crypt(Cipher.DECRYPT_MODE, eki.getEncryptionAlgorithm(), password,
            wrongZero, eki.encryptedData());
        keyBags.add(new Bag<>(PrivateKeyInfo.fromEncoded(key), bag.getBagAttributes()));
      } else if (bagId.equals(PkcsOIDs.keyBag)) {
        keyBags.add(new Bag<>(PrivateKeyInfo.fromAsn1(bag.getBagValue().asSequence()),
            bag.getBagAttributes()));
      } else if (bagId.equals(PkcsOIDs.certBag)) {
        CertBag cb = CertBag.fromAsn1(bag.getBagValue().asSequence());
        Asn1Oid certId = cb.getCertId();
        if (!(certId.equals(PkcsOIDs.x509Certificate)
              || certId.equals(XipkiOIDs.id_xipki_certtype_c509cert))) {
          throw new IOException("Unsupported certificate type: " + cb.getCertId());
        }

        byte[] encoded = cb.getCertValue().asOctetString().getOctets();
        Cert cert = certId.equals(PkcsOIDs.x509Certificate)
            ? new Cert(Certificate.fromEncoded(encoded))
            : new Cert(C509Certificate.parse(encoded));

        CertInfo certInfo = new CertInfo(cert, encoded);
        certBags.add(new Bag<>(certInfo, bag.getBagAttributes()));
      }
    }
  }

  /**
   * Creates the entries from the bags.
   * <ul>
   *   <li>Key: alias = friendlyName, else hex(localKeyId). Its certificate is the certificate
   *       with the same friendlyName, else with the same localKeyId.</li>
   *   <li>Key without friendlyName and localKeyId: if it is the only one, it gets the first
   *       certificate and alias = hex(SKI); otherwise no certificate and alias = hex(SHA-1 of
   *       the key).</li>
   *   <li>Certificate with friendlyName that is not the alias of a key: trusted certificate.</li>
   * </ul>
   */
  private void link(List<Bag<PrivateKeyInfo>> keyBags, List<Bag<CertInfo>> certBags) {
    Map<String, CertInfo> certsByName = new HashMap<>();
    Map<String, CertInfo> certsByLocalKeyId = new HashMap<>();
    for (Bag<CertInfo> bag : certBags) {
      addToPool(bag.value);
      if (bag.friendlyName != null) {
        certsByName.put(bag.friendlyName, bag.value);
      }
      if (bag.localKeyId != null) {
        certsByLocalKeyId.put(Hex.encode(bag.localKeyId), bag.value);
      }
    }

    List<PrivateKeyInfo> unnamedKeys = new ArrayList<>();
    for (Bag<PrivateKeyInfo> bag : keyBags) {
      if (bag.friendlyName == null && bag.localKeyId == null) {
        unnamedKeys.add(bag.value);
        continue;
      }

      String hexLocalKeyId = (bag.localKeyId == null) ? null : Hex.encode(bag.localKeyId);
      String alias = (bag.friendlyName != null) ? bag.friendlyName : hexLocalKeyId;
      CertInfo cert = certsByName.get(alias);
      if (cert == null && hexLocalKeyId != null) {
        cert = certsByLocalKeyId.get(hexLocalKeyId);
      }
      entries.put(alias, new Entry(bag.value, cert, cert == null ? bag.localKeyId : null));
    }

    CertInfo unnamedKeyCert = null;
    if (unnamedKeys.size() == 1 && !certBags.isEmpty()) {
      unnamedKeyCert = certBags.get(0).value;
      entries.put(Hex.encode(unnamedKeyCert.ski.value),
          new Entry(unnamedKeys.get(0), unnamedKeyCert, null));
    } else {
      for (PrivateKeyInfo key : unnamedKeys) {
        entries.put(Hex.encode(sha1(key.getEncoded())), new Entry(key, null, null));
      }
    }

    for (Bag<CertInfo> bag : certBags) {
      if (bag.friendlyName != null && bag.value != unnamedKeyCert
          && !entries.containsKey(bag.friendlyName)) {
        entries.put(bag.friendlyName, new Entry(null, bag.value, null));
      }
    }
  }

  // ---------------------------------------------------------------- store

  public void store(OutputStream stream, char[] password) throws IOException {
    Args.notNull(password, "password");

    List<SafeBag> keyBags = new ArrayList<>();
    List<SafeBag> certBags = new ArrayList<>();
    Set<Bytes> writtenCerts = new HashSet<>();

    // key entries, with the certificates of their keys
    for (Map.Entry<String, Entry> e : entries.entrySet()) {
      Entry entry = e.getValue();
      if (entry.key == null) {
        continue;
      }

      byte[] localKeyId = (entry.cert == null) ? entry.localKeyId : entry.cert.ski.value;
      List<Attribute> attrs = new ArrayList<>(2);
      if (localKeyId != null) {
        attrs.add(Attribute.ofLocalKeyId(localKeyId));
      }
      attrs.add(Attribute.ofFriendlyName(e.getKey()));

      AlgorithmIdentifier algId = pbes2Algorithm();
      byte[] encryptedKey = crypt(Cipher.ENCRYPT_MODE, algId, password, false,
          entry.key.getEncoded());
      keyBags.add(new SafeBag(PkcsOIDs.pkcs8ShroudedKeyBag,
          new EncryptedPrivateKeyInfo(algId, encryptedKey).toAsn1Primitive(),
          new Attribute.Set0(attrs)));

      if (entry.cert != null) {
        certBags.add(certBag(entry.cert, new Attribute.Set0(attrs)));
        writtenCerts.add(new Bytes(entry.cert.encoded));
      }
    }

    // trusted certificates: one bag per alias, even if the certificate is already written
    for (Map.Entry<String, Entry> e : entries.entrySet()) {
      Entry entry = e.getValue();
      if (entry.key != null) {
        continue;
      }
      writtenCerts.add(new Bytes(entry.cert.encoded));

      // Oracle trusted key usage: the extended key usages of the certificate
      List<Asn1Oid> ekus = new ArrayList<>(2);
      if (entry.cert.cert.x509cert != null) {
        Extension extn = entry.cert.cert.x509cert.getExtension(ExtensionOIDs.extendedKeyUsage);
        if (extn != null) {
          ekus.addAll(extn.getExtendedKeyUsage().getEntries());
        }
      } else {
        assert entry.cert.cert.c509cert != null;
        C509Extension extn = entry.cert.cert.c509cert.extensions()
            .get(ConstExtensionId.extKeyUsage);
        if (extn != null) {
          C509ExtKeyUsageSyntax syntax = (C509ExtKeyUsageSyntax) extn.value();
          assert syntax != null;
          for (long usage : syntax.usages()) {
            Asn1Oid oid = ConstExtendedKeyUsage.getOid(usage);
            if (oid != null) {
              ekus.add(oid);
            }
          }
        }
      }

      if (ekus.isEmpty()) {
        ekus.add(KeyPurposeOIDs.anyExtendedKeyUsage);
      }

      certBags.add(certBag(entry.cert, new Attribute.Set0(List.of(
          Attribute.ofFriendlyName(e.getKey()), Attribute.ofOraclePkcs12TrustedKeyUsage(ekus)))));
    }

    // the other certificates of the chains
    for (Entry entry : entries.values()) {
      if (entry.key == null) {
        continue;
      }

      for (CertInfo c : chain(entry)) {
        if (writtenCerts.add(new Bytes(c.encoded))) {
          certBags.add(certBag(c, new Attribute.Set0()));
        }
      }
    }

    // keys: SafeContents in data, certificates: SafeContents in encryptedData
    AlgorithmIdentifier certAlgId = pbes2Algorithm();
    byte[] encryptedCerts = crypt(Cipher.ENCRYPT_MODE, certAlgId, password, false,
        new SafeContents(certBags).getEncoded(Asn1Encoding.DER));

    byte[] authSafe = new AuthenticatedSafe(
        new ContentInfo(PkcsOIDs.data,
            new Asn1OctetString(new SafeContents(keyBags).getEncoded(Asn1Encoding.DER))),
        new ContentInfo(PkcsOIDs.encryptedData, new EncryptedData(
            new EncryptedContentInfo(PkcsOIDs.data, certAlgId, encryptedCerts)).toAsn1Primitive())
    ).getEncoded(Asn1Encoding.DER);

    // MAC
    byte[] macSalt = randomSalt();
    AlgorithmIdentifier macAlgId = AlgorithmIdentifier.ofNullParams(NistOIDs.id_sha256);
    MacData macData;
    try {
      byte[] mac = Pkcs12Pbe.calculatePbeMac(macAlgId, macSalt, ITERATIONS, password, false,
          authSafe);
      macData = new MacData(new DigestInfo(macAlgId, mac), macSalt, ITERATIONS);
    } catch (GeneralSecurityException e) {
      throw new IOException("error constructing MAC: " + e.getMessage(), e);
    }

    Pfx pfx = new Pfx(new ContentInfo(PkcsOIDs.data, new Asn1OctetString(authSafe)), macData);
    stream.write(pfx.getEncoded(Asn1Encoding.DER));
  }

  private static SafeBag certBag(CertInfo cert, Attribute.Set0 attrs) {
    CertBag certBag = new CertBag(cert.cert.type, new Asn1OctetString(cert.encoded));
    return new SafeBag(PkcsOIDs.certBag, certBag.toAsn1Primitive(), attrs);
  }

  /**
   * Returns PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC, with a random salt and IV.
   */
  private AlgorithmIdentifier pbes2Algorithm() {
    byte[] iv = new byte[16];
    crypto.getSecureRandom().nextBytes(iv);
    AlgorithmIdentifier kdf = AlgorithmIdentifier.build(PkcsOIDs.id_PBKDF2,
        new PBKDF2Params(randomSalt(), ITERATIONS,
            AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256)));
    AlgorithmIdentifier enc = new AlgorithmIdentifier(NistOIDs.id_aes256_CBC,
        new Asn1OctetString(iv));
    return AlgorithmIdentifier.build(PkcsOIDs.id_PBES2, new PBES2Parameters(kdf, enc));
  }

  private byte[] randomSalt() {
    byte[] salt = new byte[SALT_SIZE];
    crypto.getSecureRandom().nextBytes(salt);
    return salt;
  }

  // ---------------------------------------------------------------- crypto

  /**
   * Encrypts or decrypts with a PKCS#12 PBE scheme or PBES2.
   */
  private byte[] crypt(int mode, AlgorithmIdentifier algId, char[] password, boolean wrongZero,
                       byte[] data) throws IOException {
    Asn1Oid algorithm = algId.getAlgorithm();
    try {
      Cipher cipher;
      if (algorithm.on(PkcsOIDs.pkcs_12PbeIds)) {
        cipher = Pkcs12Pbe.createCipher(mode, password, algId, wrongZero);
      } else if (algorithm.equals(PkcsOIDs.id_PBES2)) {
        cipher = pbes2Cipher(mode, password, algId);
      } else {
        throw new IOException("unknown PBE algorithm: " + algorithm);
      }

      return cipher.doFinal(data);
    } catch (GeneralSecurityException | CodecException e) {
      String op = (mode == Cipher.ENCRYPT_MODE) ? "encrypting" : "decrypting";
      throw new IOException("exception " + op + " data - " + e.getMessage(), e);
    }
  }

  private Cipher pbes2Cipher(int mode, char[] password, AlgorithmIdentifier algId)
      throws GeneralSecurityException, CodecException {
    PBES2Parameters params = PBES2Parameters.fromAsn1(algId.getParameters().asSequence());
    AlgorithmIdentifier kdf = params.getKeyDerivationFunc();
    if (!PkcsOIDs.id_PBKDF2.equals(kdf.getAlgorithm())) {
      throw new NoSuchAlgorithmException("unsupported PBES2 key derivation function "
          + kdf.getAlgorithm().getId());
    }

    AlgorithmIdentifier encScheme = params.getEncryptionScheme();
    String encOid = encScheme.getAlgorithm().getId();
    Object[] scheme = PBES2_SCHEMES.get(encOid);
    if (scheme == null) {
      throw new NoSuchAlgorithmException(
          "unknown key size for PBES2 encryption scheme " + encOid);
    }

    Asn1Primitive encParams = encScheme.getParameters();
    if (!(encParams instanceof Asn1OctetString)) {
      throw new NoSuchAlgorithmException("unknown encParams: " + encParams);
    }

    PBKDF2Params pbkdf2 = PBKDF2Params.fromAsn1(kdf.getParameters().asSequence());
    byte[] keyBytes = crypto.pbkdf2(pbkdf2.isDefaultPrf() ? null : pbkdf2.getPrf(),
        password, pbkdf2.salt(), pbkdf2.iterationCount(), (Integer) scheme[0]);

    String transformation = (scheme[1] != null) ? (String) scheme[1] : encOid;
    String keyAlgorithm = (scheme[2] != null) ? (String) scheme[2] : encOid;
    SecretKeySpec key = new SecretKeySpec(keyBytes, keyAlgorithm);
    XiArrays.clear(keyBytes);

    Cipher cipher = crypto.newCipher(transformation);
    cipher.init(mode, key, new IvParameterSpec(((Asn1OctetString) encParams).getOctets()),
        crypto.getSecureRandom());
    return cipher;
  }

  private static byte[] sha1(byte[] data) {
    try {
      return crypto.newMessageDigest("SHA-1").digest(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("SHA-1 is not available", e);
    }
  }

  private static byte[] sha256_20(byte[] data) {
    try {
      return Arrays.copyOf(crypto.newMessageDigest("SHA-256").digest(data), 20);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }

}
