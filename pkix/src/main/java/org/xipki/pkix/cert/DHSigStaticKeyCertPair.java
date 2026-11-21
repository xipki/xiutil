// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x500.X500Name;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * DHSig Static Key Cert Pair.
 * RFC 6955.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class DHSigStaticKeyCertPair {

  private final PrivateKey privateKey;

  private final BigInteger serialNumber;

  public DHSigStaticKeyCertPair(PrivateKey privateKey, BigInteger serialNumber) {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public PrivateKey privateKey() {
    return privateKey;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public abstract byte[] encodedIssuer();

  public abstract byte[] encodedSubject();

  /**
   * C509-based DHSig Static Key Cert Pair.
   * RFC 6955.
   *
   * @author Lijun Liao (xipki)
   */
  public static class C509 extends DHSigStaticKeyCertPair {

    private final C509Name issuer;

    private final C509Name subject;

    private final byte[] encodedIssuer;

    private final byte[] encodedSubject;

    public C509(PrivateKey privateKey, C509Cert certificate) {
      super(privateKey, Args.notNull(certificate, "certificate").serialNumber());

      this.issuer = certificate.issuer();
      this.subject = certificate.subject();
      try {
        this.encodedIssuer  = (issuer == null) ? null : issuer.getEncoded();
        this.encodedSubject = subject.getEncoded();
      } catch (Exception ex) {
        throw new IllegalArgumentException("error encoding certificate", ex);
      }
    }

    public C509Name issuer() {
      return issuer;
    }

    public C509Name subject() {
      return subject;
    }

    @Override
    public byte[] encodedIssuer() {
      return Arrays.copyOf(encodedIssuer, encodedIssuer.length);
    }

    @Override
    public byte[] encodedSubject() {
      return Arrays.copyOf(encodedSubject, encodedSubject.length);
    }

  }

  /**
   * X509-based DHSig Static Key Cert Pair.
   * RFC 6955.
   *
   * @author Lijun Liao (xipki)
   */
  public static class X509 extends DHSigStaticKeyCertPair {

    private final X500Name issuer;

    private final X500Name subject;

    private final byte[] encodedIssuer;

    private final byte[] encodedSubject;

    public X509(PrivateKey privateKey, X509Cert certificate)
        throws CodecException {
      super(privateKey, Args.notNull(certificate, "certificate").serialNumber());

      try {
        this.encodedIssuer  = certificate.issuer().getEncoded();
        this.encodedSubject = certificate.subject().getEncoded();
      } catch (Exception ex) {
        throw new IllegalArgumentException("error encoding certificate", ex);
      }
      this.issuer = X500Name.fromEncoded(this.encodedIssuer);
      this.subject = X500Name.fromEncoded(this.encodedSubject);
    }

    public X500Name issuer() {
      return issuer;
    }

    public X500Name subject() {
      return subject;
    }

    @Override
    public byte[] encodedIssuer() {
      return Arrays.copyOf(encodedIssuer, encodedIssuer.length);
    }

    @Override
    public byte[] encodedSubject() {
      return Arrays.copyOf(encodedSubject, encodedSubject.length);
    }

  }
}
