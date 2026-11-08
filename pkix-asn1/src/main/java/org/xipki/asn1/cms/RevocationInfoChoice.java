// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.CertificateList;
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
 * RevocationInfoChoice ::= CHOICE {
 *     crl CertificateList,
 *     other [1] IMPLICIT OtherRevocationInfoFormat }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevocationInfoChoice extends Asn1Encodable {

  public static class Set0 extends AbstractSet0<RevocationInfoChoice> {

    public Set0(RevocationInfoChoice... entries) {
      super(entries);
    }

    public Set0(List<RevocationInfoChoice> entries) {
      super(entries);
    }

    protected Set0(Asn1Set set) throws CodecException {
      super(set);
    }

    public static Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new Set0(set);
    }

    @Override
    protected RevocationInfoChoice newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return RevocationInfoChoice.fromAsn1(coll.getObjectAt(index));
    }

    public boolean hasOtherCrl() {
      for (RevocationInfoChoice c : entries) {
        if (c.hasOther()) {
          return true;
        }
      }
      return false;
    }

  }

  private final CertificateList crl;

  private final OtherRevocationInfoFormat other;

  public static RevocationInfoChoice fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");

    OtherRevocationInfoFormat other = null;

    if (asn1 instanceof Asn1Sequence) {
      return ofCrl(CertificateList.fromAsn1((Asn1Sequence) asn1));
    } else if (asn1 instanceof Asn1TaggedObject) {
      Asn1TaggedObject t = (Asn1TaggedObject) asn1;
      int tagNo = t.getTagNo();
      if (tagNo == 1) {
        return ofOther(OtherRevocationInfoFormat.fromAsn1(t.getImplicitSequenceBase()));
      }
    }

    throw new CodecException("invalid asn1 element");
  }

  private RevocationInfoChoice(CertificateList crl, OtherRevocationInfoFormat other) {
    this.crl = crl;
    this.other = other;
  }

  public static RevocationInfoChoice ofCrl(CertificateList crl) {
    return new RevocationInfoChoice(Args.notNull(crl, "crl"), null);
  }

  public static RevocationInfoChoice ofOther(OtherRevocationInfoFormat other) {
    return new RevocationInfoChoice(null, Args.notNull(other, "other"));
  }

  public boolean hasOther() {
    return other != null;
  }

  public CertificateList getCrl() {
    return crl;
  }

  public OtherRevocationInfoFormat getOther() {
    return other;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return crl != null ? crl.toAsn1Primitive()
        : Asn1TaggedObject.newImplicit(1, other);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (crl != null) {
      return crl.toStringWithLineSep(buf, indentLevel, "crl");
    }

    return other.toStringWithLineSep(buf, indentLevel, "other");
  }
}
