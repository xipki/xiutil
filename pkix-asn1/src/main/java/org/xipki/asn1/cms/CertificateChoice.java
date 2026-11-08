// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSet0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 5652:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * CertificateChoices ::= CHOICE {
 *     certificate     Certificate,
 *     extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
 *     v1AttrCert  [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
 *     v2AttrCert  [2] IMPLICIT AttributeCertificateV2,
 *     other       [3] IMPLICIT OtherCertificateFormat }
 * </pre>
 *
 * CertificateChoices shall be a typo, we use the single form CertificateChoice here.
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateChoice extends Asn1Encodable {

  public static class Set0 extends AbstractSet0<CertificateChoice> {

    public Set0(CertificateChoice... entries) {
      super(entries);
    }

    public Set0(List<CertificateChoice> entries) {
      super(entries);
    }

    protected Set0(Asn1Set set) throws CodecException {
      super(set);
    }

    public static CertificateChoice.Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new CertificateChoice.Set0(set);
    }

    @Override
    protected CertificateChoice newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return CertificateChoice.fromAsn1(coll.getObjectAt(index));
    }

    // we do not support attribute certificate
    public boolean hasV1AttributeCertificate() {
      for (CertificateChoice c : entries) {
        if (c.hasV1AttrCert()) {
          return true;
        }
      }
      return false;
    }

    public boolean hasV2AttributeCertificate() {
      for (CertificateChoice c : entries) {
        if (c.hasV2AttrCert()) {
          return true;
        }
      }
      return false;
    }

    public boolean hasOtherCertificate() {
      for (CertificateChoice c : entries) {
        if (c.hasOther()) {
          return true;
        }
      }
      return false;
    }

  }

  private final Certificate certificate;

  private final Asn1Sequence v2AttrCert;

  private final OtherCertificateFormat other;

  public static CertificateChoice fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");

    if (asn1 instanceof Asn1Sequence) {
      return ofCertificate(Certificate.fromAsn1((Asn1Sequence) asn1));
    } else if (asn1 instanceof Asn1TaggedObject) {
      Asn1TaggedObject t = (Asn1TaggedObject) asn1;
      int tagNo = t.getTagNo();
      if (tagNo == 2) {
        return ofV2AttrCert(t.getImplicitSequenceBase());
      } else if (tagNo == 3) {
        return ofOther(OtherCertificateFormat.fromAsn1(t.getImplicitSequenceBase()));
      }
    }

    throw new CodecException("invalid asn1 element");
  }

  private CertificateChoice(Certificate certificate, Asn1Sequence v2AttrCert,
                            OtherCertificateFormat other) {
    this.certificate = certificate;
    this.v2AttrCert = v2AttrCert;
    this.other = other;
  }

  public static CertificateChoice ofCertificate(Certificate certificate) {
    return new CertificateChoice(Args.notNull(certificate, "certificate"), null, null);
  }

  public static CertificateChoice ofV2AttrCert(Asn1Sequence v2AttrCert) {
    return new CertificateChoice(null, Args.notNull(v2AttrCert, "v2AttrCert"), null);
  }

  public static CertificateChoice ofOther(OtherCertificateFormat other) {
    return new CertificateChoice(null, null, Args.notNull(other, "other"));
  }

  public boolean hasV3Cert() {
    return certificate != null;
  }

  public boolean hasV1AttrCert() {
    return false;
  }

  public boolean hasV2AttrCert() {
    return v2AttrCert != null;
  }

  public boolean hasOther() {
    return other != null;
  }

  public Certificate getCertificate() {
    return certificate;
  }

  public Asn1Sequence getV2AttrCert() {
    return v2AttrCert;
  }

  public OtherCertificateFormat getOther() {
    return other;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return certificate != null ? certificate.toAsn1Primitive()
        : v2AttrCert != null ? Asn1TaggedObject.newImplicit(2, v2AttrCert)
        : Asn1TaggedObject.newImplicit(3, other);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (certificate != null) {
      return certificate.toStringWithLineSep(buf, indentLevel, "certificate");
    }

    if (v2AttrCert != null) {
      return v2AttrCert.toStringWithLineSep(buf, indentLevel, "v2AttrCert");
    }

    return other.toStringWithLineSep(buf, indentLevel, "other");
  }
}
