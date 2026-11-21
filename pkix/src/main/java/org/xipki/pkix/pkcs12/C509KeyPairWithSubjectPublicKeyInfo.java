// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.c509.C509SubjectPublicKey;

import java.security.KeyPair;

/**
 * Key Pair With Subject Public Key information.
 *
 * @author Lijun Liao (xipki)
 */
public class C509KeyPairWithSubjectPublicKeyInfo {

  private final KeyPair keypair;

  private final C509SubjectPublicKey subjectPublicKeyInfo;

  public C509KeyPairWithSubjectPublicKeyInfo(
      KeyPair keypair, C509SubjectPublicKey subjectPublicKeyInfo) {
    this.keypair = keypair;
    this.subjectPublicKeyInfo = subjectPublicKeyInfo;
  }

  public KeyPair keypair() {
    return keypair;
  }

  public C509SubjectPublicKey subjectPublicKeyInfo() {
    return subjectPublicKeyInfo;
  }

}
