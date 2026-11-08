// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * RFC 8226: TelephoneNumberRange
 * <pre>
 *  TelephoneNumberRange ::= SEQUENCE {
 *     start TelephoneNumber,
 *     count INTEGER (2..MAX),
 *     ...
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TelephoneNumberRange extends Asn1Encodable {

  private final Asn1IA5String start;

  private final Asn1Integer count;

  private final List<Asn1Primitive> extraFields;

  public static TelephoneNumberRange fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeMin(seq, "seq", 2);
    Asn1IA5String start = seq.getIA5StringAt(0);
    Asn1Integer count = seq.getNonNegativeIntegerAt(1);

    int i = 2;
    List<Asn1Primitive> extraFields = new ArrayList<>(size - i);
    for (; i < size; i++) {
      extraFields.add(seq.getObjectAt(i));
    }
    return new TelephoneNumberRange(start, count, extraFields);
  }

  public TelephoneNumberRange(String start, int count) {
    this(Asn1Util.toIA5String(start), Asn1Util.toInteger(count), null);
  }

  public TelephoneNumberRange(String start, BigInteger count) {
    this(Asn1Util.toIA5String(start), Asn1Util.toInteger(count), null);
  }

  public TelephoneNumberRange(Asn1IA5String start, Asn1Integer count) {
    this(start, count, null);
  }

  public TelephoneNumberRange(Asn1IA5String start, Asn1Integer count,
                              List<Asn1Primitive> extraFields) {
    TNEntry.assertValidTelephoneNumber(Args.notNull(start, "start").getString(), "start");
    Args.notNull(count, "count");

    if (count.getValue().compareTo(BigInteger.TWO) < 0) {
      throw new IllegalArgumentException("count not in (2..MAX)");
    }

    this.start = start;
    this.count = count;
    this.extraFields = extraFields;
  }

  public Asn1IA5String getStart() {
    return start;
  }

  public Asn1Integer getCount() {
    return count;
  }

  public String start() {
    return start.getString();
  }

  public BigInteger count() {
    return count.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    List<Asn1Encodable> v = new LinkedList<>();
    v.add(start);
    v.add(count);
    if (extraFields != null) {
      v.addAll(extraFields);
    }
    return new Asn1Sequence(v);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    start.toStringNoLineSep(buf, indentLevel, "start", true);
    count.toStringNoLineSep(buf, indentLevel, "count", true);
    if (extraFields != null) {
      for (Asn1Primitive m : extraFields) {
        m.toString(buf, indentLevel).append("\n");
      }
    }
    return deleteLastNewLine(buf);
  }
}
