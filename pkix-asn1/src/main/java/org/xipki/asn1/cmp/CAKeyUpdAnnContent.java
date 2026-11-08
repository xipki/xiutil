// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * CAKeyUpdAnnContent ::= SEQUENCE {
 *     oldWithNew   CMPCertificate, -- old pub signed with new priv
 *     newWithOld   CMPCertificate, -- new pub signed with old priv
 *     newWithNew   CMPCertificate  -- new pub signed with new priv
 * }
 *
 * @author Lijun Liao (xipki)
 */
public class CAKeyUpdAnnContent extends Asn1Encodable {

  private final CMPCertificate oldWithNew;
  private final CMPCertificate newWithOld;
  private final CMPCertificate newWithNew;

  public static CAKeyUpdAnnContent fromAsn1(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CAKeyUpdAnnContent fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    CMPCertificate oldWithNew = CMPCertificate.fromAsn1(seq.getSequenceAt(0));
    CMPCertificate newWithOld = CMPCertificate.fromAsn1(seq.getSequenceAt(1));
    CMPCertificate newWithNew = CMPCertificate.fromAsn1(seq.getSequenceAt(2));
    return new CAKeyUpdAnnContent(oldWithNew, newWithOld, newWithNew);
  }

  public CAKeyUpdAnnContent(CMPCertificate oldWithNew, CMPCertificate newWithOld,
                            CMPCertificate newWithNew) {
    this.oldWithNew = Args.notNull(oldWithNew, "oldWithNew");
    this.newWithOld = Args.notNull(newWithOld, "newWithOld");
    this.newWithNew = Args.notNull(newWithNew, "newWithNew");
  }

  public CMPCertificate getOldWithNew() {
    return oldWithNew;
  }

  public CMPCertificate getNewWithOld() {
    return newWithOld;
  }

  public CMPCertificate getNewWithNew() {
    return newWithNew;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(oldWithNew, newWithOld, newWithNew);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    oldWithNew.toStringWithLineSep(buf, indentLevel, "oldWithNew", true);
    newWithOld.toStringWithLineSep(buf, indentLevel, "newWithOld", true);
    return newWithNew.toStringWithLineSep(buf, indentLevel, "newWithNew", false);
  }

}
