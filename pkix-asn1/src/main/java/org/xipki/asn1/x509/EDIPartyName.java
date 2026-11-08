// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.DirectoryString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * EDIPartyName ::= SEQUENCE {
 *     nameAssigner   [0]     DirectoryString OPTIONAL,
 *     partyName      [1]     DirectoryString }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EDIPartyName extends Asn1Encodable {

  private final DirectoryString nameAssigner;
  private final DirectoryString partyName;

  public static EDIPartyName fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static EDIPartyName fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;

    // CHOICE -> EXPLICIT
    DirectoryString nameAssigner = seq.isNotTaggedAt(index, 0) ? null
        : DirectoryString.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    // CHOICE -> EXPLICIT
    DirectoryString partyName = seq.isNotTaggedAt(index, 1) ? null
        : DirectoryString.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    Asn1Util.checkSequenceEnd(index, size);

    return new EDIPartyName(nameAssigner, partyName);
  }

  public EDIPartyName(DirectoryString nameAssigner, DirectoryString partyName) {
    this.nameAssigner = nameAssigner;
    this.partyName = Args.notNull(partyName, "partyName");
  }

  public EDIPartyName(String nameAssigner, String partyName) {
    this.nameAssigner = nameAssigner == null ? null : new DirectoryString(nameAssigner);
    this.partyName = new DirectoryString(Args.notNull(partyName, "partyName"));
  }

  public DirectoryString getNameAssigner() {
    return nameAssigner;
  }

  public String nameAssigner() {
    return nameAssigner == null ? null : nameAssigner.string();
  }

  public DirectoryString getPartyName() {
    return partyName;
  }

  public String partyName() {
    return partyName.string();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        nameAssigner == null ? null : Asn1TaggedObject.newExplicit(0, nameAssigner),
        Asn1TaggedObject.newExplicit(1, partyName));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (nameAssigner != null) {
      nameAssigner.toStringNoLineSep(buf, indentLevel, "nameAssigner", true);
    }

    if (partyName != null) {
      partyName.toStringNoLineSep(buf, indentLevel, "partyName", true);
    }

    if (nameAssigner != null || partyName != null) {
      deleteLastNewLine(buf);
    }
    return buf;
  }

}
