// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.PrimitiveType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <code>UserNotice</code> class, used in
 * <code>CertificatePolicies</code> X509 extensions (in policy
 * qualifiers).
 * <pre>
 * UserNotice ::= SEQUENCE {
 *      noticeRef        NoticeReference OPTIONAL,
 *      explicitText     DisplayText OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class UserNotice extends Asn1Encodable {

  private final NoticeReference noticeRef;
  private final DisplayText explicitText;

  public UserNotice(NoticeReference noticeRef, DisplayText explicitText) {
    this.noticeRef = noticeRef;
    this.explicitText = explicitText;
  }

  public UserNotice(NoticeReference noticeRef, String str) {
    this(noticeRef, new DisplayText(str));
  }

  public static UserNotice fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);
    int index = 0;
    NoticeReference noticeRef = seq.notHasType(index, PrimitiveType.SEQUENCE) ? null
        : NoticeReference.fromAsn1(seq.getSequenceAt(index++));

    DisplayText explicitText =
        seq.hasAnyType(index, PrimitiveType.IA5_STRING, PrimitiveType.VISIBLE_STRING,
            PrimitiveType.UTF8_STRING, PrimitiveType.BMP_STRING)
        ? DisplayText.fromAsn1(seq.getString(index++)) : null;

    Asn1Util.checkSequenceEnd(index, size);
    return new UserNotice(noticeRef, explicitText);
  }

  public NoticeReference getNoticeRef() {
    return noticeRef;
  }

  public DisplayText getExplicitText() {
    return explicitText;
  }

  public String explicitText() {
    return explicitText == null ? null : explicitText.string();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(noticeRef, explicitText);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (noticeRef != null) {
      noticeRef.toStringWithLineSep(buf, indentLevel, "noticeRef", true);
    }

    if (explicitText != null) {
      explicitText.toStringNoLineSep(buf, indentLevel, "explicitText", true);
    }

    return deleteLastNewLine(buf);
  }

}
