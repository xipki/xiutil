// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.codec.util.Args;
import org.xipki.crypto.core.HashAlgo;

import java.util.Arrays;

/**
 * Issuer Hash.
 * RFC 6960.
 *
 * @author Lijun Liao (xipki)
 */
public class X509IssuerHash {

  private final HashAlgo hashAlgo;

  private final byte[] issuerNameHash;

  private final byte[] issuerKeyHash;

  public X509IssuerHash(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
    this.issuerNameHash = Args.notNull(issuerNameHash, "issuerNameHash");
    this.issuerKeyHash = Args.notNull(issuerKeyHash, "issuerKeyHash");

    final int len = hashAlgo.length();
    Args.range(issuerNameHash.length, "issuerNameHash.length", len, len);
    Args.range(issuerKeyHash.length, "issuerKeyHash.length", len, len);
  }

  public X509IssuerHash(HashAlgo hashAlgo, X509Cert issuerCert) {
    this.hashAlgo = Args.notNull(hashAlgo, "hashAlgo");
    byte[] encodedName = Args.notNull(issuerCert, "issuerCert").subject().getEncoded();
    byte[] encodedKey = issuerCert.subjectPublicKeyInfo().subjectPublicKey();
    this.issuerNameHash = hashAlgo.hash(encodedName);
    this.issuerKeyHash  = hashAlgo.hash(encodedKey);
  }

  public HashAlgo hashAlgo() {
    return hashAlgo;
  }

  public byte[] issuerNameHash() {
    return Arrays.copyOf(issuerNameHash, issuerNameHash.length);
  }

  public byte[] issuerKeyHash() {
    return Arrays.copyOf(issuerKeyHash, issuerKeyHash.length);
  }

  public boolean match(HashAlgo hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash) {
    return this.hashAlgo == Args.notNull(hashAlgo, "hashAlgo")
        && Arrays.equals(this.issuerNameHash, Args.notNull(issuerNameHash, "issuerNameHash"))
        && Arrays.equals(this.issuerKeyHash, Args.notNull(issuerKeyHash, "issuerKeyHash"));
  }

}
