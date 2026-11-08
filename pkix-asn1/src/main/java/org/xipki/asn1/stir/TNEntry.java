// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC8226
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::= BEGIN
 *
 * TNEntry ::= CHOICE {
 *    spc    [0] ServiceProviderCode,
 *    range  [1] TelephoneNumberRange,
 *    one    [2] TelephoneNumber
 * }
 *
 * ServiceProviderCode ::= IA5String
 *
 *  -- SPCs may be OCNs, various SPIDs, or other SP identifiers
 *  -- from the telephone network.
 *
 *  TelephoneNumberRange ::= SEQUENCE {
 *     start TelephoneNumber,
 *     count INTEGER (2..MAX),
 *     ...
 *  }
 *
 *  TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TNEntry extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<TNEntry> {

    public Seq1(TNEntry... entries) {
      super(entries);
    }

    public Seq1(List<TNEntry> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected TNEntry newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return TNEntry.fromAsn1(coll.getTaggedAt(index));
    }
  }

  private final Asn1IA5String spc;

  private final TelephoneNumberRange range;

  private final Asn1IA5String one;

  private TNEntry(Asn1IA5String spc, TelephoneNumberRange range, Asn1IA5String one) {
    this.spc = spc;
    this.range = range;
    this.one = one;
  }

  private TNEntry(String spc, TelephoneNumberRange range, String one) {
    this.spc = (spc == null) ? null : new Asn1IA5String(spc);
    this.range = range;

    if (one == null) {
      this.one = null;
    } else {
      assertValidTelephoneNumber(one, "one");
      this.one = new Asn1IA5String(one);
    }
  }

  static void assertValidTelephoneNumber(String str, String name) {
    Args.range(str.length(), name, 1, 15);
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (!((c >= '0' && c <= '9') || c == '#' || c == '*')) {
        throw new IllegalArgumentException("invalid char in " + name + ": '" + c + "'");
      }
    }
  }

  public static TNEntry fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    int tagNo = asn1.getTagNo();
    if (tagNo == 0) {
      return ofSpc(asn1.getExplicitIA5StringBase().getString());
    } else if (tagNo == 1) {
      return ofRange(TelephoneNumberRange.fromAsn1(asn1.getExplicitSequenceBase()));
    } else if (tagNo == 2) {
      return ofOne(asn1.getExplicitIA5StringBase().getString());
    } else {
      throw new CodecException("invalid tagNo " + tagNo);
    }
  }

  public static TNEntry ofSpc(String spc) {
    return new TNEntry(Args.notNull(spc, "spc"), null, null);
  }

  public static TNEntry ofRange(TelephoneNumberRange range) {
    return new TNEntry((Asn1IA5String) null, Args.notNull(range, "range"), null);
  }

  public static TNEntry ofOne(String one) {
    return new TNEntry(null, null, Args.notNull(one, "one"));
  }

  public Asn1IA5String getSpc() {
    return spc;
  }

  public TelephoneNumberRange getRange() {
    return range;
  }

  public Asn1IA5String getOne() {
    return one;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return spc != null ? Asn1TaggedObject.newExplicit(0, spc)
        : range != null ? Asn1TaggedObject.newExplicit(1, range)
        : Asn1TaggedObject.newExplicit(2, one);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (spc != null) {
      return spc.toStringNoLineSep(buf, indentLevel, "spc");
    } else if (range != null) {
      return range.toStringWithLineSep(buf, indentLevel, "range");
    } else {
      return one.toStringNoLineSep(buf, indentLevel, "one");
    }
  }
}
