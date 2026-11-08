// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * DHSig Static Key Cert Pair.
 * RFC 6955.
 *
 * @author Lijun Liao (xipki)
 */
public class DHSigStaticKeyCertPair {

  private final PrivateKey privateKey;

  private final X500Name issuer;

  private final X500Name subject;

  private final BigInteger serialNumber;

  private final byte[] encodedIssuer;

  private final byte[] encodedSubject;

  public DHSigStaticKeyCertPair(PrivateKey privateKey, X509Cert certificate) throws CodecException {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.serialNumber = Args.notNull(certificate, "certificate").serialNumber();

    try {
      this.encodedIssuer  = certificate.issuer().getEncoded();
      this.encodedSubject = certificate.subject().getEncoded();
    } catch (Exception ex) {
      throw new IllegalArgumentException("error encoding certificate", ex);
    }
    this.issuer = X500Name.fromEncoded(this.encodedIssuer);
    this.subject = X500Name.fromEncoded(this.encodedSubject);
  }

  public PrivateKey privateKey() {
    return privateKey;
  }

  public X500Name issuer() {
    return issuer;
  }

  public X500Name subject() {
    return subject;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public byte[] encodedIssuer() {
    return Arrays.copyOf(encodedIssuer, encodedIssuer.length);
  }

  public byte[] encodedSubject() {
    return Arrays.copyOf(encodedSubject, encodedSubject.length);
  }

}
