// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;

/**
 * PKCS12 Key Store Wrapper.
 *
 * @author Lijun Liao (xipki)
 */
public class X509Pkcs12KeyStoreWrapper {

  private final byte[] keystore;

  private Pkcs12KeyStore keystoreObject;

  private SubjectPublicKeyInfo subjectPublicKeyInfo;

  public X509Pkcs12KeyStoreWrapper(byte[] keystore) {
    this.keystore = Args.notNull(keystore, "keystore");
  }

  public byte[] keystore() {
    return keystore;
  }

  public Pkcs12KeyStore keystoreObject() {
    return keystoreObject;
  }

  public void setKeystoreObject(Pkcs12KeyStore keystoreObject) {
    this.keystoreObject = keystoreObject;
  }

  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

  public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
    this.subjectPublicKeyInfo = subjectPublicKeyInfo;
  }

}
