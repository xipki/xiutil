// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees [0] GeneralSubtrees OPTIONAL,
 *   excludedSubtrees  [1] GeneralSubtrees OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class NameConstraints extends Asn1Encodable {

  private final GeneralSubtrees permitted;

  private final GeneralSubtrees excluded;

  public static NameConstraints fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static NameConstraints fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.notNull(seq, "seq").size();
    int index = 0;
    GeneralSubtrees permitted = seq.isNotTaggedAt(index, 0) ? null
        : GeneralSubtrees.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    GeneralSubtrees excluded = seq.isNotTaggedAt(index, 1) ? null
        : GeneralSubtrees.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Asn1Util.checkSequenceEnd(index, size);
    return new NameConstraints(permitted, excluded);
  }

  public NameConstraints(GeneralSubtrees permitted, GeneralSubtrees excluded) {
    this.permitted = permitted;
    this.excluded  = excluded;
  }

  public GeneralSubtrees getPermittedSubtrees() {
    return permitted;
  }

  public GeneralSubtrees getExcludedSubtrees() {
    return excluded;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        permitted == null ? null : Asn1TaggedObject.newImplicit(0, permitted),
        excluded  == null ? null : Asn1TaggedObject.newImplicit(1, excluded));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (permitted != null) {
      permitted.toStringWithLineSep(buf, indentLevel, "permitted", true);
    }

    if (excluded != null) {
      excluded.toStringWithLineSep(buf, indentLevel, "excluded", true);
    }

    if (permitted != null || excluded != null) {
      deleteLastNewLine(buf);
    }

    return buf;
  }
}
