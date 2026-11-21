// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.cert.C509Certificate;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.util.Args;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Computes the hash values used in C509 OCSP messages for one hash algorithm.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Hasher {

  private final int algorithm;

  private final String jcaName;

  private final int truncatedLength;

  public C509Hasher(int algorithm, int truncatedLength) throws NoSuchAlgorithmException {
    this.algorithm = algorithm;
    String name = ConstHashAlgorithm.name(algorithm);
    int slash = name.indexOf('/');
    this.jcaName = slash < 0 ? name : name.substring(0, slash);
    int length = ConstHashAlgorithm.hashValueLength(algorithm);
    this.truncatedLength = Args.max(truncatedLength, "truncatedLength", length);
    MessageDigest.getInstance(jcaName);
  }

  public int algorithm() {
    return algorithm;
  }

  public int truncatedLength() {
    return truncatedLength;
  }

  private byte[] hash(byte[] data) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(jcaName);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    byte[] h = md.digest(data);
    return h.length == truncatedLength ? h : Arrays.copyOf(h, truncatedLength);
  }

  /*
  public byte[] hash(C509Certificate cert) {
    return hash(cert.getEncoded());
  }
   */

  public C509HashedId hashedIdForCert(C509Certificate cert) {
    return new C509HashedId(hash(cert.getEncoded()));
  }

}
