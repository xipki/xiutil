// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PolicyInformation extends Asn1Encodable {

  /**
   * SEQUENCE SIZE (1..MAX) OF PolicyInformation
   */
  public static class Seq1 extends AbstractSeq1<PolicyInformation> {

    public Seq1(PolicyInformation... entries) {
      super(entries);
    }

    public Seq1(List<PolicyInformation> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected PolicyInformation newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PolicyInformation.fromAsn1(coll.getSequenceAt(index));
    }

  }

  /**
   * SEQUENCE OF PolicyInformation
   */
  public static class Seq0 extends AbstractSeq0<PolicyInformation> {

    public Seq0(PolicyInformation... entries) {
      super(entries);
    }

    public Seq0(List<PolicyInformation> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected PolicyInformation newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PolicyInformation.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final Asn1Oid policyIdentifier;
  private final PolicyQualifierInfo.Seq1 policyQualifiers;

  public static PolicyInformation fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid policyIdentifier = seq.getOidAt(0);
    PolicyQualifierInfo.Seq1 policyQualifiers = (size == 1) ? null
        : PolicyQualifierInfo.Seq1.fromAsn1(seq.getSequenceAt(1));
    return new PolicyInformation(policyIdentifier, policyQualifiers);
  }

  public PolicyInformation(Asn1Oid policyIdentifier) {
    this(policyIdentifier, null);
  }

  public PolicyInformation(Asn1Oid policyIdentifier, PolicyQualifierInfo.Seq1 policyQualifiers) {
    this.policyIdentifier = Args.notNull(policyIdentifier, "policyIdentifier");
    this.policyQualifiers = policyQualifiers;
  }

  public Asn1Oid getPolicyIdentifier() {
    return policyIdentifier;
  }

  public PolicyQualifierInfo.Seq1 getPolicyQualifiers() {
    return policyQualifiers;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(policyIdentifier, policyQualifiers);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    policyIdentifier.toStringNoLineSep(buf, indentLevel, "policyIdentifier", true);
    if (policyQualifiers != null) {
      policyQualifiers.toStringWithLineSep(buf, indentLevel, "policyQualifiers", true);
    }
    return deleteLastNewLine(buf);
  }
}
