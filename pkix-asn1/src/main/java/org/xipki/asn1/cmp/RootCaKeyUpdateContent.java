// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * GenMsg:    {id-it 20}, RootCaCertValue | &lt; absent &gt;
 * GenRep:    {id-it 18}, RootCaKeyUpdateContent | &lt; absent &gt;
 * <p>
 * RootCaCertValue ::= CMPCertificate
 * <p>
 * RootCaKeyUpdateValue ::= RootCaKeyUpdateContent
 * <p>
 * RootCaKeyUpdateContent ::= SEQUENCE {
 *   newWithNew       CMPCertificate,
 *   newWithOld   [0] CMPCertificate OPTIONAL,
 *   oldWithNew   [1] CMPCertificate OPTIONAL
 * }
 *
 * @author Lijun Liao (xipki)
 */
public class RootCaKeyUpdateContent extends Asn1Encodable {

  private final CMPCertificate newWithNew;
  private final CMPCertificate newWithOld;
  private final CMPCertificate oldWithNew;

  public RootCaKeyUpdateContent(CMPCertificate newWithNew, CMPCertificate newWithOld,
                                CMPCertificate oldWithNew) {
    this.newWithNew = Args.notNull(newWithNew, "newWithNew");
    this.newWithOld = newWithOld;
    this.oldWithNew = oldWithNew;
  }

  public static RootCaKeyUpdateContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    CMPCertificate newWithNew = CMPCertificate.fromAsn1(seq.getSequenceAt(0));

    int index = 1;
    CMPCertificate newWithOld = seq.isNotTaggedAt(index, 0) ? null
        : CMPCertificate.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    CMPCertificate oldWithNew = seq.isNotTaggedAt(index, 1) ? null
        : CMPCertificate.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    Asn1Util.checkSequenceEnd(index, size);
    return new RootCaKeyUpdateContent(newWithNew, newWithOld, oldWithNew);
  }

  public CMPCertificate getNewWithNew() {
    return newWithNew;
  }

  public CMPCertificate getNewWithOld() {
    return newWithOld;
  }

  public CMPCertificate getOldWithNew() {
    return oldWithNew;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    Asn1TaggedObject asn1NewWithOld = (newWithOld == null) ? null
        : Asn1TaggedObject.newExplicit(0, newWithOld);

    Asn1TaggedObject asn1OldWithNew = (oldWithNew == null) ? null
        : Asn1TaggedObject.newExplicit(1, oldWithNew);

    return Asn1Sequence.buildIgnoreNull(newWithNew, asn1NewWithOld, asn1OldWithNew);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (newWithOld != null) {
      newWithOld.toStringWithLineSep(buf, indentLevel, "newWithOld", true);
    }

    if (oldWithNew != null) {
      oldWithNew.toStringWithLineSep(buf, indentLevel, "oldWithNew", true);
    }

    newWithNew.toStringWithLineSep(buf, indentLevel, "newWithNew", true);

    return deleteLastNewLine(buf);
  }

}
