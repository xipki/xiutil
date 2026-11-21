// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.C509Cert;
import org.xipki.pkix.util.C509Util;
import org.xipki.pkix.util.KeyUtil;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Keypair With certificate record.
 *
 * @author Lijun Liao (xipki)
 */
public class C509KeypairWithCert {

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final C509Cert[] certChain;

  public C509KeypairWithCert(PrivateKey key, C509Cert[] certChain) {
    this.key = Args.notNull(key, "key");
    this.certChain = Args.notNull(certChain, "certChain");
    Args.min(certChain.length, "certChain.length", 1);
    this.publicKey = certChain[0].publicKey();
  }

  /**
   * Read keypair and certificate from the keystore with external certificate.
   * The specified stream remains open after this method returns.
   *
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param cert external certificate.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static C509KeypairWithCert fromPKCS12Keystore(
      InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, C509Cert cert)
      throws XiSecurityException {
    return fromPKCS12Keystore(keystoreStream, keystorePassword,
        keyname, keyPassword, cert == null ? null : new C509Cert[] {cert});
  }

  /**
   * Read keypair and certificate from the keystore with external certificate
   * chain.
   * <p>
   * The specified stream remains open after this method returns.
   *
   * @param keystoreStream the inputstream containing the keystore.
   * @param keystorePassword the password to read the keystore.
   * @param keyname the alias of key entry in the keystore.
   * @param keyPassword the password to read the key entry.
   * @param certchain external certificate chain.
   * @return keypair and certificate pair read from the keystore.
   * @throws XiSecurityException if Security error occurs.
   */
  public static C509KeypairWithCert fromPKCS12Keystore(
      InputStream keystoreStream, char[] keystorePassword,
      String keyname, char[] keyPassword, C509Cert[] certchain)
      throws XiSecurityException {
    Args.notNull(keystoreStream, "keystoreStream");
    Args.notNull(keystorePassword, "keystorePassword");
    Args.notNull(keyPassword, "keyPassword");

    Pkcs12KeyStore keystore = KeyUtil.loadPKCS12KeyStore(keystoreStream, keystorePassword);
    return fromKeystore(keystore, keyname, keyPassword, certchain);
  }

  public static C509KeypairWithCert fromKeystore(
      Pkcs12KeyStore keystore, String keyname, char[] keyPassword, C509Cert[] certchain)
      throws XiSecurityException {
    Args.notNull(keyPassword, "keyPassword");

    try {
      String tmpKeyname = keyname;
      if (tmpKeyname == null) {
        Set<String> aliases = keystore.aliases();
        for (String alias : aliases) {
          if (keystore.isKeyEntry(alias)) {
            tmpKeyname = alias;
            break;
          }
        }
      } else {
        if (!keystore.isKeyEntry(tmpKeyname)) {
          throw new XiSecurityException("unknown key named " + tmpKeyname);
        }
      }

      PrivateKeyInfo keyInfo = keystore.getKey(tmpKeyname);
      PrivateKey key = KeyInfoUtil.getPrivateKey(keyInfo);

      Set<C509Cert> caCerts = new HashSet<>();

      C509Cert cert;
      if (certchain != null && certchain.length > 0) {
        cert = certchain[0];
        final int n = certchain.length;
        if (n > 1) {
          caCerts.addAll(Arrays.asList(certchain).subList(1, n));
        }
      } else {
        C509Certificate keyCert = keystore.getC509Certificate(tmpKeyname);
        if (keyCert == null) {
          throw new XiSecurityException("no certificate for key '" + tmpKeyname
              + "' in the keystore, and no certificate chain is given");
        }

        cert = new C509Cert(keyCert);
      }

      // empty for a key without certificate in the keystore
      List<C509Certificate> certsInKeystore = keystore.getC509CertificateChain(tmpKeyname);
      if (certsInKeystore.size() > 1) {
        for (int i = 1; i < certsInKeystore.size(); i++) {
          caCerts.add(new C509Cert(certsInKeystore.get(i)));
        }
      }

      C509Cert[] certificateChain = C509Util.buildCertPath(cert, caCerts);

      return new C509KeypairWithCert(key, certificateChain);
    } catch (ClassCastException | InvalidKeySpecException | CodecException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }
  } // method fromKeystore

  public PrivateKey getKey() {
    return key;
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  public C509Cert[] certChain() {
    return certChain;
  }

}
