// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.PolicyQualifierOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Policy qualifiers, used in the X509V3 CertificatePolicies
 * extension.
 *
 * <pre>
 *   PolicyQualifierInfo ::= SEQUENCE {
 *       policyQualifierId  PolicyQualifierId,
 *       qualifier          ANY DEFINED BY policyQualifierId }
 *
 *  PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PolicyQualifierInfo extends Asn1Encodable {

  /**
   * SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo
   */
  public static class Seq1 extends AbstractSeq1<PolicyQualifierInfo> {

    public Seq1(PolicyQualifierInfo... entries) {
      super(entries);
    }

    public Seq1(List<PolicyQualifierInfo> entries) {
      super(entries);
    }

    private Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected PolicyQualifierInfo newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return PolicyQualifierInfo.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final Asn1Oid policyQualifierId;

  private final Asn1Primitive qualifier;

  private boolean parsed;

  private Asn1IA5String cps;

  private UserNotice userNotice;

  private PolicyQualifierInfo(Asn1Oid policyQualifierId, Asn1Primitive qualifier) {
    this.policyQualifierId = Args.notNull(policyQualifierId, "policyQualifierId");
    this.qualifier = Args.notNull(qualifier, "qualifier");
  }

  public static PolicyQualifierInfo createNoParse(
      Asn1Oid policyQualifierId, Asn1Encodable qualifier) {
    return new PolicyQualifierInfo(policyQualifierId,
        Args.notNull(qualifier, "qualifier").toAsn1Primitive());
  }

  public static PolicyQualifierInfo create(Asn1Oid policyQualifierId, Asn1Encodable qualifier)
      throws CodecException {
    PolicyQualifierInfo r = createNoParse(policyQualifierId, qualifier);
    r.parseValue();
    return r;
  }

  private static PolicyQualifierInfo create2(Asn1Oid policyQualifierId, Asn1Encodable qualifier) {
    PolicyQualifierInfo r = createNoParse(policyQualifierId, qualifier);
    r.parsed = true;
    return r;
  }

  public static PolicyQualifierInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid policyQualifierId = seq.getOidAt(0);
    Asn1Primitive qualifier = seq.getObjectAt(1);
    PolicyQualifierInfo r = new PolicyQualifierInfo(policyQualifierId, qualifier);
    r.parseValue();
    return r;
  }

  public static PolicyQualifierInfo ofCps(String value) {
    return ofCps(new Asn1IA5String(Args.notNull(value, "value")));
  }

  public static PolicyQualifierInfo ofCps(Asn1IA5String value) {
    Asn1IA5String asn1Value = Args.notNull(value, "value");
    PolicyQualifierInfo r = create2(PolicyQualifierOIDs.id_qt_cps, asn1Value);
    r.cps = asn1Value;
    return r;
  }

  public static PolicyQualifierInfo ofUserNotice(UserNotice value) {
    Args.notNull(value, "value");
    PolicyQualifierInfo r = create2(PolicyQualifierOIDs.id_qt_unotice, value);
    r.userNotice = value;
    return r;
  }

  public Asn1Oid getPolicyQualifierId() {
    return policyQualifierId;
  }

  public Asn1Primitive getQualifier() {
    return qualifier;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(policyQualifierId, qualifier);
  }

  public Asn1IA5String getCps() {
    return cps;
  }

  public String cps() {
    return Asn1Util.fromAsn1(cps);
  }

  public UserNotice getUserNotice() {
    return userNotice;
  }

  private void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    String id = policyQualifierId.getId();
    if (id.equals(PolicyQualifierOIDs.id_qt_cps.getId())) {
      cps = qualifier.asIA5String();
    } else if (id.equals(PolicyQualifierOIDs.id_qt_unotice.getId())) {
      userNotice = UserNotice.fromAsn1(qualifier.asSequence());
    }

    parsed = true;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    policyQualifierId.toStringNoLineSep(buf, indentLevel, "policyQualifierId", true);
    return qualifier.toStringWithLineSep(buf, indentLevel, "qualifier");
  }

}
