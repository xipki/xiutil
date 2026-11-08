// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.est;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 10002:
 * <pre>
 *   DEFINITIONS IMPLICIT TAGS ::=
 *
 *   at-cmc-changeSubjectName ATTRIBUTE ::= {
 *       TYPE ChangeSubjectName IDENTIFIED BY id-cmc-changeSubjectName }
 *
 *   id-cmc-changeSubjectName OBJECT IDENTIFIER ::= { id-cmc 36 }
 *
 *   ChangeSubjectName ::= SEQUENCE {
 *     subject             Name OPTIONAL,
 *     subjectAlt          [1] GeneralNames OPTIONAL
 *   }
 *   (WITH COMPONENTS {..., subject PRESENT} |
 *    WITH COMPONENTS {..., subjectAlt PRESENT} )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ChangeSubjectName extends Asn1Encodable {

  private final X500Name subject;

  private final GeneralNames subjectAlt;

  public static ChangeSubjectName fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ChangeSubjectName fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;
    X500Name subject = seq.notHasSequence(index) ? null
        : X500Name.fromAsn1(seq.getSequenceAt(index++));
    GeneralNames subjectAlt = seq.isNotTaggedAt(index, 1) ? null
        : GeneralNames.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Asn1Util.checkSequenceEnd(index, size);
    return new ChangeSubjectName(subject, subjectAlt);
  }

  public ChangeSubjectName(X500Name subject, GeneralNames subjectAlt) {
    if (subject == null && subjectAlt == null) {
      throw new IllegalArgumentException("subject and subjectAlt shall not be both null");
    }
    this.subject = subject;
    this.subjectAlt = subjectAlt;
  }

  public X500Name getSubject() {
    return subject;
  }

  public GeneralNames getSubjectAlt() {
    return subjectAlt;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(subject,
        subjectAlt == null ? null : Asn1TaggedObject.newImplicit(1, subjectAlt));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (subject != null) {
      subject.toStringNoLineSep(buf, indentLevel, "subject", true);
    }

    if (subjectAlt != null) {
      subjectAlt.toStringWithLineSep(buf, indentLevel, "subjectAlt", true);
    }

    return deleteLastNewLine(buf);
  }
}
