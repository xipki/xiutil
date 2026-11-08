// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

/**
 * X509 CRL record.
 *
 * @author Lijun Liao (xipki)
 */

public class X509Crl {

  private final Object sync = new Object();

  private final CertificateList x509;

  private byte[] encoded;

  public X509Crl(CertificateList crl) {
    this(crl, null);
  }

  public X509Crl(CertificateList crl, byte[] encoded) {
    this.x509 = Args.notNull(crl, "crl");
    this.encoded = encoded;
  }

  public byte[] getEncoded() {
    if (encoded != null) {
      return encoded;
    }

    synchronized (sync) {
      try {
        encoded = x509.getEncoded();
      } catch (Exception ex) {
        throw new IllegalStateException("error encoding CRL", ex);
      }
      return encoded;
    }
  }

  public BigInteger crlNumber() {
    Extension extn = x509.getExtension(ExtensionOIDs.cRLNumber);
    return extn == null ? null : extn.getCRLNumber().getValue();
  }

  public BigInteger baseCrlNumber() {
    Extension extn = x509.getExtension(ExtensionOIDs.deltaCRLIndicator);
    return extn == null ? null : extn.getDeltaCRLIndicator().getValue();
  }

  public X500Name issuer() {
    return x509.getIssuer();
  }

  public Instant thisUpdate() {
    return x509.thisUpdate();
  }

  public Instant nextUpdate() {
    return x509.nextUpdate();
  }

  public Extensions extensions() {
    return x509.getExtensions();
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return x509.getExtension(extensionId);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) return true;

    if (!(obj instanceof X509Crl)) return false;

    return Arrays.equals(getEncoded(), ((X509Crl) obj).getEncoded());
  }

  @Override
  public String toString() {
    return x509.toString();
  }

}
