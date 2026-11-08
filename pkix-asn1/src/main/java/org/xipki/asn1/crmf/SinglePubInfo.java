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

import java.util.List;

/**
 * <pre>
 * SinglePubInfo ::= SEQUENCE {
 *        pubMethod    INTEGER {
 *           dontCare    (0),
 *           x500        (1),
 *           web         (2),
 *           ldap        (3) },
 *       pubLocation  GeneralName OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SinglePubInfo extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<SinglePubInfo> {

    public Seq1(SinglePubInfo... entries) {
      super(entries);
    }

    public Seq1(List<SinglePubInfo> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected SinglePubInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return SinglePubInfo.fromAsn1(coll.getSequenceAt(index));
    }
  }

  public static final Asn1Integer dontCare = new Asn1Integer(0);
  public static final Asn1Integer x500 = new Asn1Integer(1);
  public static final Asn1Integer web = new Asn1Integer(2);
  public static final Asn1Integer ldap = new Asn1Integer(3);

  private final Asn1Integer pubMethod;
  private final GeneralName pubLocation;

  public static SinglePubInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Integer pubMethod = seq.getNonNegativeIntegerAt(0);
    GeneralName pubLocation = (size == 1) ? null : GeneralName.fromAsn1(seq.getTaggedAt(1));
    return new SinglePubInfo(pubMethod, pubLocation);
  }

  public SinglePubInfo(int pubMethod, GeneralName pubLocation) {
    this(new Asn1Integer(pubMethod), pubLocation);
  }

  public SinglePubInfo(Asn1Integer pubMethod, GeneralName pubLocation) {
    this.pubMethod = Args.notNull(pubMethod, "pubMethod");
    this.pubLocation = pubLocation;
  }

  public Asn1Integer getPubMethod() {
    return pubMethod;
  }

  public GeneralName getPubLocation() {
    return pubLocation;
  }

  public int pubMethod() {
    return pubMethod.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(pubMethod, pubLocation);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    pubMethod.toStringNoLineSep(buf, indentLevel, "pubMethod", true);

    if (pubLocation != null) {
      pubLocation.toStringWithLineSep(buf, indentLevel, "pubLocation", true);
    }

    return deleteLastNewLine(buf);
  }

}
