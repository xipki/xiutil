// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * <pre>
 * CertId ::= SEQUENCE {
 *     issuer       GeneralName,
 *     serialNumber INTEGER }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertId extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<CertId> {

    public Seq1(CertId... entries) {
      super(entries);
    }

    public Seq1(List<CertId> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected CertId newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return CertId.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final GeneralName issuer;
  private final Asn1Integer serialNumber;

  public static CertId fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    GeneralName issuer = GeneralName.fromAsn1(seq.getTaggedAt(0));
    Asn1Integer serialNumber = seq.getNonNegativeIntegerAt(1);
    return new CertId(issuer, serialNumber);
  }

  public CertId(GeneralName issuer, BigInteger serialNumber) {
    this(issuer, new Asn1Integer(serialNumber));
  }

  public CertId(GeneralName issuer, Asn1Integer serialNumber) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
  }

  public GeneralName getIssuer() {
    return issuer;
  }

  public Asn1Integer getSerialNumber() {
    return serialNumber;
  }

  public BigInteger serialNumber() {
    return serialNumber.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(issuer, serialNumber);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuer.toStringWithLineSep(buf, indentLevel, "issuer", true);
    serialNumber.toStringNoLineSep(buf, indentLevel, "serialNumber", true);

    return deleteLastNewLine(buf);
  }

}
