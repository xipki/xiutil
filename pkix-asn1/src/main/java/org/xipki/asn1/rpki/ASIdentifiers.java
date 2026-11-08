// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * ASIdentifiers.
 * <pre>
 * ASIdentifiers ::= SEQUENCE {
 *     asnum  [0] EXPLICIT ASIdentifierChoice OPTIONAL,
 *     rdi    [1] EXPLICIT ASIdentifierChoice OPTIONAL}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdentifiers extends Asn1Encodable {

  private final ASIdentifierChoice asnum;

  private final ASIdentifierChoice rdi;

  public ASIdentifiers(ASIdentifierChoice asnum, ASIdentifierChoice rdi) {
    this.asnum = asnum;
    this.rdi = rdi;
  }

  public static ASIdentifiers fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ASIdentifiers fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);
    int index = 0;
    ASIdentifierChoice asnum = seq.isNotTaggedAt(index, 0) ? null
        : ASIdentifierChoice.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    ASIdentifierChoice rdi = seq.isNotTaggedAt(index, 1) ? null
        : ASIdentifierChoice.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    Asn1Util.checkSequenceEnd(index, size);
    return new ASIdentifiers(asnum, rdi);
  }

  public ASIdentifierChoice getAsnum() {
    return asnum;
  }

  public ASIdentifierChoice getRdi() {
    return rdi;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        asnum == null ? null : Asn1TaggedObject.newExplicit(0, asnum),
        rdi   == null ? null : Asn1TaggedObject.newExplicit(1, rdi));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (asnum != null) {
      asnum.toStringWithLineSep(buf, indentLevel, "asnum");
    }

    if (rdi != null) {
      if (asnum != null) {
        buf.append("\n");
      }
      rdi.toStringWithLineSep(buf, indentLevel, "rdi");
    }
    return buf;
  }
}
