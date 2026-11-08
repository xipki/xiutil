// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * RecipientKeyIdentifier ::= SEQUENCE {
 *     subjectKeyIdentifier SubjectKeyIdentifier,
 *     date                 GeneralizedTime OPTIONAL,
 *     other                OtherKeyAttribute OPTIONAL
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RecipientKeyIdentifier extends Asn1Encodable {

  private final Asn1OctetString subjectKeyIdentifier;
  private final Asn1GeneralizedTime date;
  private final OtherKeyAttribute other;

  public RecipientKeyIdentifier(Asn1OctetString subjectKeyIdentifier,
                                Asn1GeneralizedTime date, OtherKeyAttribute other) {
    this.subjectKeyIdentifier = Args.notNull(subjectKeyIdentifier, "subjectKeyIdentifier");
    this.date = date;
    this.other = other;
  }

  public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, Instant date,
                                OtherKeyAttribute other) {
    this.subjectKeyIdentifier = new Asn1OctetString(
        Args.notNull(subjectKeyIdentifier, "subjectKeyIdentifier"));
    this.date = (date == null) ? null : new Asn1GeneralizedTime(date);
    this.other = other;
  }

  public RecipientKeyIdentifier(byte[] subjectKeyIdentifier) {
    this(subjectKeyIdentifier, null, null);
  }

  public static RecipientKeyIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    Asn1OctetString subjectKeyIdentifier = seq.getOctetStringAt(0);

    int index = 1;
    Asn1GeneralizedTime date = seq.notHasGeneralizedTime(index) ? null
        : seq.getGeneralizedTimeAt(index++);

    OtherKeyAttribute other = seq.notHasSequence(index) ? null
        : OtherKeyAttribute.fromAsn1(seq.getSequenceAt(index++));

    Asn1Util.checkSequenceEnd(index, size);
    return new RecipientKeyIdentifier(subjectKeyIdentifier, date, other);
  }

  public Asn1OctetString getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public Asn1GeneralizedTime getDate() {
    return date;
  }

  public OtherKeyAttribute getOtherKeyAttribute() {
    return other;
  }

  public byte[] subjectKeyIdentifier() {
    return subjectKeyIdentifier.getOctets();
  }

  public Instant date() {
    return Asn1Util.fromAsn1(date);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(subjectKeyIdentifier, date, other);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    subjectKeyIdentifier.toStringWithLineSep(buf, indentLevel, "subjectKeyIdentifier", true);

    if (date != null) {
      date.toStringNoLineSep(buf, indentLevel, "date", true);
    }

    if (other != null) {
      other.toStringWithLineSep(buf, indentLevel, "other", true);
    }

    return deleteLastNewLine(buf);
  }
}
