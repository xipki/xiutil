// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PolicyMappings V3 extension, described in RFC3280.
 *
 * <pre>
 *    PolicyMapping ::= SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 * </pre>
 *
 * @see <a href="https://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a>
 *
 * @author Lijun Liao (xipki)
 */
public class PolicyMapping extends Asn1Encodable {

  /**
   * SEQUENCE SIZE (1..MAX) OF PolicyMapping
   */
  public static class Seq1 extends AbstractSeq1<PolicyMapping> {

    public Seq1(PolicyMapping... entries) {
      super(entries);
    }

    public Seq1(List<PolicyMapping> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected PolicyMapping newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return PolicyMapping.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final Asn1Oid issuerDomainPolicy;
  private final Asn1Oid subjectDomainPolicy;

  public PolicyMapping(Asn1Oid issuerDomainPolicy, Asn1Oid subjectDomainPolicy) {
    this.issuerDomainPolicy = Args.notNull(issuerDomainPolicy, "issuerDomainPolicy");
    this.subjectDomainPolicy = Args.notNull(subjectDomainPolicy, "subjectDomainPolicy");
  }

  public static PolicyMapping fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid issuerDomainPolicy = seq.getOidAt(0);
    Asn1Oid subjectDomainPolicy = seq.getOidAt(1);
    return new PolicyMapping(issuerDomainPolicy, subjectDomainPolicy);
  }

  public Asn1Oid getIssuerDomainPolicy() {
    return issuerDomainPolicy;
  }

  public Asn1Oid getSubjectDomainPolicy() {
    return subjectDomainPolicy;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(issuerDomainPolicy, subjectDomainPolicy);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuerDomainPolicy.toStringNoLineSep(buf, indentLevel, "issuerDomainPolicy", true);
    return subjectDomainPolicy.toStringNoLineSep(buf, indentLevel, "subjectDomainPolicy");
  }
}
