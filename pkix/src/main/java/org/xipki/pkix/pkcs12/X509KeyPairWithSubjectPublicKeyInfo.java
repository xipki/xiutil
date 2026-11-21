// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.pkix.util.X509Util;

import java.security.KeyPair;

/**
 * Key Pair With Subject Public Key information.
 *
 * @author Lijun Liao (xipki)
 */
public class X509KeyPairWithSubjectPublicKeyInfo {

  private final KeyPair keypair;

  private final SubjectPublicKeyInfo subjectPublicKeyInfo;

  public X509KeyPairWithSubjectPublicKeyInfo(
      KeyPair keypair, SubjectPublicKeyInfo subjectPublicKeyInfo) {
    this.keypair = keypair;
    this.subjectPublicKeyInfo = X509Util.toRfc3279Style(subjectPublicKeyInfo);
  }

  public KeyPair keypair() {
    return keypair;
  }

  public SubjectPublicKeyInfo subjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

}
