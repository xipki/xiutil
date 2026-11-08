// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.IntegerSeq;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * <code>NoticeReference</code> class, used in
 * <code>CertificatePolicies</code> X509 V3 extensions (in policy qualifiers).
 *
 * <pre>
 *  NoticeReference ::= SEQUENCE {
 *      organization     DisplayText,
 *      noticeNumbers    SEQUENCE OF INTEGER }
 * </pre>
 *
 * @see PolicyQualifierInfo
 * @see PolicyInformation
 *
 * @author Lijun Liao (xipki)
 */
public class NoticeReference extends Asn1Encodable {

  private final DisplayText organization;
  private final IntegerSeq noticeNumbers;

  public NoticeReference(String organization, List<BigInteger> numbers) {
    Args.noNullElements(numbers, "numbers");
    this.organization = new DisplayText(organization);
    this.noticeNumbers = IntegerSeq.ofBigIntegers(0, numbers);
  }

  /**
   * Creates a new <code>NoticeReference</code> instance.
   *
   * @param organization displayText
   * @param noticeNumbers an <code>ASN1EncodableVector</code> value
   */
  public NoticeReference(DisplayText organization, IntegerSeq noticeNumbers) {
    this.organization = Args.notNull(organization, "organization");
    this.noticeNumbers = Args.notNull(noticeNumbers, "noticeNumbers");
  }

  public static NoticeReference fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    DisplayText organization = DisplayText.fromAsn1(seq.getString(0));
    IntegerSeq noticeNumbers = new IntegerSeq(0,
        seq.getSequenceAt(1).toIntegers().toArray(new Asn1Integer[0]));
    return new NoticeReference(organization, noticeNumbers);
  }

  public DisplayText getOrganization()
  {
      return organization;
  }

  public IntegerSeq getNoticeNumbers() {
    return noticeNumbers;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(organization, noticeNumbers);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    organization.toStringNoLineSep(buf, indentLevel, "organization", true);
    noticeNumbers.toStringWithLineSep(buf, indentLevel, "noticeNumbers", true);

    return deleteLastNewLine(buf);
  }

}
