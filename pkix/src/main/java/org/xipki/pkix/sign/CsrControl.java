// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.c509.C509BytesSubjectPublicKey;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.util.StringUtil;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.util.C509Util;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.crypto.core.SecretKeyWithAlias;
import org.xipki.pkix.util.X509Util;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.conf.FileOrValue;
import org.xipki.util.conf.KeystoreConf;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CSR Control settings.
 *
 * @author Lijun Liao (xipki)
 */
public class CsrControl {

  private final SecretKeyWithAlias defaultKemMasterKey;

  private final Map<String, SecretKeyWithAlias> kemMasterKeys;

  private final List<X509Cert> peerX509Certs;

  private final List<C509Cert> peerC509Certs;

  public CsrControl() {
    this.defaultKemMasterKey = null;
    this.peerX509Certs = null;
    this.peerC509Certs = null;
    this.kemMasterKeys = Collections.emptyMap();
  }

  public CsrControl(CsrControlConf conf) throws InvalidConfException {
    if (conf.peerCerts() == null) {
      this.peerX509Certs = null;
      this.peerC509Certs = null;
    } else {
      try {
        String certPem = conf.peerCerts().readContent();
        if (certPem.contains("BEGIN C509 CERTIFICATE")) {
          this.peerX509Certs = null;
          this.peerC509Certs = C509Util.parseCerts(StringUtil.toUtf8Bytes(certPem));
        } else {
          this.peerX509Certs = X509Util.parseCerts(StringUtil.toUtf8Bytes(certPem));
          this.peerC509Certs = null;
        }
      } catch (Exception e) {
        throw new InvalidConfException(e);
      }
    }

    KeystoreConf kemConf = conf.kem();
    if (kemConf == null) {
      this.kemMasterKeys = Collections.emptyMap();
      this.defaultKemMasterKey = null;
      return;
    }

    Map<String, SecretKeyWithAlias> tmpKemMasterKeys = new HashMap<>();
    KeyStore ks;
    char[] password;

    try {
      password = Passwords.resolvePassword(kemConf.password());
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    try (InputStream is = new ByteArrayInputStream(kemConf.keystore().readContent())) {
      ks = KeyUtil.loadKeyStore(kemConf.type(), is, password);
    } catch (XiSecurityException | IOException ex) {
      throw new InvalidConfException("error loading keystore", ex);
    }

    try {
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) {
          continue;
        }

        Key key = ks.getKey(alias, password);
        if (key instanceof SecretKey) {
          // we consider only Secret key
          tmpKemMasterKeys.put(alias, new SecretKeyWithAlias(alias, (SecretKey) key));
        }
      }
    } catch (GeneralSecurityException ex) {
      throw new InvalidConfException("invalid KEM pop configuration", ex);
    }

    if (tmpKemMasterKeys.isEmpty()) {
      this.kemMasterKeys = Collections.emptyMap();
      this.defaultKemMasterKey = null;
    } else {
      this.kemMasterKeys = Collections.unmodifiableMap(tmpKemMasterKeys);
      String alias = this.kemMasterKeys.keySet().iterator().next();
      this.defaultKemMasterKey = this.kemMasterKeys.get(alias);
    }
  }

  public List<X509Cert> peerX509Certs() {
    return peerX509Certs;
  }

  public List<C509Cert> peerC509Certs() {
    return peerC509Certs;
  }

  public KemEncapKey generateKemEncapKey(SubjectPublicKeyInfo publicKey)
      throws XiSecurityException {
    if (defaultKemMasterKey == null) {
      return null;
    }

    return KemUtil.generateKemEncapKey(publicKey, defaultKemMasterKey);
  }


  public KemEncapKey generateKemEncapKey(C509SubjectPublicKey publicKey)
      throws XiSecurityException {
    if (defaultKemMasterKey == null) {
      return null;
    }

    return KemUtil.generateKemEncapKey((C509BytesSubjectPublicKey) publicKey, defaultKemMasterKey);
  }

  /**
   * CSR Control configuration.
   */
  public static class CsrControlConf {

    private FileOrValue peerCerts;

    private KeystoreConf kem;

    public FileOrValue peerCerts() {
      return peerCerts;
    }

    public void setPeerCerts(FileOrValue peerCerts) {
      this.peerCerts = peerCerts;
    }

    public KeystoreConf kem() {
      return kem;
    }

    public void setKem(KeystoreConf kem) {
      this.kem = kem;
    }

    public static CsrControlConf parse(JsonMap json) throws CodecException {
      CsrControlConf ret = new CsrControlConf();

      JsonMap map = json.getMap("kem");
      if (map != null) {
        ret.setKem(KeystoreConf.parse(map));
      }

      ret.setPeerCerts(FileOrValue.parse(json.getMap("peerCerts")));
      return ret;
    }
  }

}
