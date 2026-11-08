// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.x509.Certificate;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * CMPCertificate ::= CHOICE {
 *    x509v3PKCert    Certificate
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CMPCertificate extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<CMPCertificate> {

    public Seq1(CMPCertificate... entries) {
      super(entries);
    }

    public Seq1(List<CMPCertificate> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected CMPCertificate newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return CMPCertificate.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Certificate x509v3PKCert;

  public static CMPCertificate fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Util.readAsn1Object(encoded));
  }

  public static CMPCertificate fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    if (asn1 instanceof Asn1Sequence) {
      return ofX509v3PKCert(Certificate.fromAsn1((Asn1Sequence) asn1));
    } else {
      throw new CodecException("invalid asn1 type");
    }
  }

  private CMPCertificate(Certificate x509v3PKCert) {
    if (x509v3PKCert.version() != 2) {
      throw new IllegalArgumentException("only v3 (2) certificates allowed");
    }

    this.x509v3PKCert = x509v3PKCert;
  }

  public static CMPCertificate ofX509v3PKCert(Certificate x509v3PKCert) {
    return new CMPCertificate(Args.notNull(x509v3PKCert, "x509v3PKCert"));
  }

  public Certificate getX509v3PKCert() {
    return x509v3PKCert;
  }

  public boolean hasX509v3PKCert() {
    return x509v3PKCert != null;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return x509v3PKCert.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return x509v3PKCert.toString(buf, indentLevel);
  }
}
