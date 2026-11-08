// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs10;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * PKCS10 CertificationRequestInfo object.
 * <pre>
 *  CertificationRequestInfo ::= SEQUENCE {
 *   version           INTEGER { v1(0) } (v1,...),
 *   subject           Name,
 *   subjectPKInfo     SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes    [0] Attributes{{ CRIAttributes }}
 *  }
 *
 *  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 *  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *    type    ATTRIBUTE.&amp;id({IOSet}),
 *    values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificationRequestInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final X500Name subject;
  private final SubjectPublicKeyInfo subjectPKInfo;
  private final Attribute.Set0 attributes;

  public CertificationRequestInfo(
      X500Name subject, SubjectPublicKeyInfo pkInfo, Attribute.Set0 attributes) {
    this(Asn1Integer.ZERO, subject, pkInfo, attributes);
  }

  public CertificationRequestInfo(
      Asn1Integer version, X500Name subject,
      SubjectPublicKeyInfo pkInfo, Attribute.Set0 attributes) {
    this.version = Args.notNull(version, "version");
    this.subject = Args.notNull(subject, "subject");
    this.subjectPKInfo = Args.notNull(pkInfo, "pkInfo");
    this.attributes = Args.notNull(attributes, "attributes");
  }

  public static CertificationRequestInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 4);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    X500Name subject = X500Name.fromAsn1(seq.getSequenceAt(1));
    SubjectPublicKeyInfo subjectPKInfo = SubjectPublicKeyInfo.fromAsn1(seq.getSequenceAt(2));

    // some CertificationRequestInfo objects seem to treat this field as optional.
    int index = 3;
    Attribute.Set0 attributes = seq.isNotTaggedAt(index, 0) ? new Attribute.Set0()
        : Attribute.Set0.fromAsn1(seq.getSetTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);

    return new CertificationRequestInfo(version, subject, subjectPKInfo, attributes);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public X500Name getSubject() {
    return subject;
  }

  public SubjectPublicKeyInfo getSubjectPKInfo() {
    return subjectPKInfo;
  }

  public Attribute.Set0 getAttributes() {
    return attributes;
  }

  public int version() {
    return version.intValueExact();
  }

  public Attribute getAttribute(Asn1Oid attributeType) {
    if (attributes != null) {
      for (Attribute attr : attributes) {
        if (attr.getAttrType().equals(attributeType)) {
          return attr;
        }
      }
    }

    return null;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, subject, subjectPKInfo,
        Asn1TaggedObject.newImplicit(0, attributes));
  }

  @Override
  protected String getTitle() {
    return "CertificationRequestInfo";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    subject.toStringNoLineSep(buf, indentLevel, "subject", true);
    subjectPKInfo.toStringWithLineSep(buf, indentLevel, "subjectPKInfo", true);
    return attributes.toStringWithLineSep(buf, indentLevel, "attributes");
  }

}
