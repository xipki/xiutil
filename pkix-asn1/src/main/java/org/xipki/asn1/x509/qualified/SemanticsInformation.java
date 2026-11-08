// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.asn1.x509.GeneralNames;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * The SemanticsInformation object.
 * <pre>
 *       SemanticsInformation ::= SEQUENCE {
 *         semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
 *         nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL }
 *         (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
 *          WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
 *
 *     NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF
 *         GeneralName
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SemanticsInformation extends Asn1Encodable {

  private final Asn1Oid semanticsIdentifier;
  private final GeneralNames nameRegistrationAuthorities;

  public static SemanticsInformation fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;
    Asn1Oid semanticsIdentifier = seq.notHasOid(index) ? null : seq.getOidAt(index++);
    GeneralNames nameRegistrationAuthorities = seq.notHasSequence(index) ? null
        : GeneralNames.fromAsn1(seq.getSequenceAt(index++));
    Asn1Util.checkSequenceEnd(index, size);
    return new SemanticsInformation(semanticsIdentifier, nameRegistrationAuthorities);
  }

  public SemanticsInformation(Asn1Oid semanticsIdentifier, GeneralNames generalNames) {
    if (semanticsIdentifier == null && generalNames == null) {
      throw new IllegalArgumentException("at least one of semanticsIdentifier and " +
          "generalNames shall not be null");
    }
    this.semanticsIdentifier = semanticsIdentifier;
    this.nameRegistrationAuthorities = generalNames;
  }

  public SemanticsInformation(Asn1Oid semanticsIdentifier) {
    this(semanticsIdentifier, null);
  }

  public SemanticsInformation(GeneralNames generalNames) {
    this(null, generalNames);
  }

  public Asn1Oid getSemanticsIdentifier() {
    return semanticsIdentifier;
  }

  public GeneralNames getNameRegistrationAuthorities() {
    return nameRegistrationAuthorities;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(semanticsIdentifier, nameRegistrationAuthorities);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (semanticsIdentifier != null) {
      semanticsIdentifier.toStringNoLineSep(buf, indentLevel, "semanticsIdentifier", true);
    }

    if (nameRegistrationAuthorities != null) {
      nameRegistrationAuthorities.toStringWithLineSep(buf, indentLevel,
          "nameRegistrationAuthorities", true);
    }

    return deleteLastNewLine(buf);
  }

}
