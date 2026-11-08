// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.PrimitiveType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KEKIdentifier ::= SEQUENCE {
 *     keyIdentifier  OCTET STRING,
 *     date           GeneralizedTime OPTIONAL,
 *     other          OtherKeyAttribute OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KEKIdentifier extends Asn1Encodable {

  private final Asn1OctetString keyIdentifier;
  private final Asn1GeneralizedTime date;
  private final OtherKeyAttribute  other;

  public KEKIdentifier(byte[] keyIdentifier, Instant date, OtherKeyAttribute other) {
    this(Asn1Util.toOctetString(keyIdentifier), Asn1Util.toGeneralizedDate(date), other);
  }

  public KEKIdentifier(Asn1OctetString keyIdentifier, Asn1GeneralizedTime date,
                       OtherKeyAttribute other) {
    this.keyIdentifier = Args.notNull(keyIdentifier, "keyIdentifier");
    this.date = date;
    this.other = other;
  }

  public static KEKIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    Asn1OctetString keyIdentifier = seq.getOctetStringAt(0);

    int index = 1;
    Asn1GeneralizedTime date = seq.notHasType(index, PrimitiveType.GENERALIZED_TIME) ? null
                : seq.getGeneralizedTimeAt(index++);
    OtherKeyAttribute other = seq.notHasType(index, PrimitiveType.SEQUENCE) ? null
                : OtherKeyAttribute.fromAsn1(seq.getSequenceAt(index++));

    if (index != size) {
      throw CodecException.seqWithUnexpectedElements();
    }

    return new KEKIdentifier(keyIdentifier, date, other);
  }

  public Asn1OctetString getKeyIdentifier() {
    return keyIdentifier;
  }

  public Asn1GeneralizedTime getDate() {
    return date;
  }

  public OtherKeyAttribute getOther() {
    return other;
  }

  public byte[] keyIdentifier() {
    return keyIdentifier.getOctets();
  }

  public Instant date() {
    return Asn1Util.fromAsn1(date);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(keyIdentifier, date, other);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    keyIdentifier.toStringWithLineSep(buf, indentLevel, "keyIdentifier", true);

    if (date != null) {
      date.toStringNoLineSep(buf, indentLevel, "date", true);
    }

    if (other != null) {
      other.toStringWithLineSep(buf, indentLevel, "other", true);
    }

    return deleteLastNewLine(buf);
  }

}
