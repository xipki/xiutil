// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.c509.crl.C509CertificateList;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.name.C509NameVariant;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.id.ExtensionOIDs;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

/**
 * X509 CRL record.
 *
 * @author Lijun Liao (xipki)
 */

public class C509Crl {

  private final Object sync = new Object();

  private final org.xipki.c509.crl.C509CertificateList c509;

  private byte[] encoded;

  public C509Crl(org.xipki.c509.crl.C509CertificateList crl) {
    this(crl, null);
  }

  public C509Crl(org.xipki.c509.crl.C509CertificateList crl, byte[] encoded) {
    this.c509 = Args.notNull(crl, "crl");
    this.encoded = encoded;
  }

  public byte[] getEncoded() {
    if (encoded != null) {
      return encoded;
    }

    synchronized (sync) {
      try {
        encoded = c509.getEncoded();
      } catch (Exception ex) {
        throw new IllegalStateException("error encoding CRL", ex);
      }
      return encoded;
    }
  }

  public C509CertificateList getC509() {
    return c509;
  }

  public BigInteger crlNumber() {
    return BigInteger.valueOf(c509.header().crlNumber());
  }

  public BigInteger baseCrlNumber() {
    Long v = c509.header().baseCrlNumber();
    return v == null ? null : BigInteger.valueOf(v);
  }

  public C509NameVariant issuer() {
    return c509.header().authority();
  }

  public Instant thisUpdate() {
    return c509.header().thisUpdate();
  }

  public Instant nextUpdate() {
    return c509.header().nextUpdate();
  }

  public C509Extensions extensions() {
    return c509.header().extensions();
  }

  public C509Extension getExtension(long extensionId) {
    return c509.header().extensions().get(extensionId);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509Crl)) return false;

    return Arrays.equals(getEncoded(), ((C509Crl) obj).getEncoded());
  }

  @Override
  public String toString() {
    return c509.toString();
  }

}
