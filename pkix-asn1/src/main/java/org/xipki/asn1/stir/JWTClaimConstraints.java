// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimConstraints ::= SEQUENCE {
 *   mustInclude    [0] JWTClaimNames OPTIONAL,
 *     -- The listed claim names MUST appear in the PASSporT
 *     -- in addition to iat, orig, and dest.  If absent, iat, orig,
 *     -- and dest MUST appear in the PASSporT.
 *   permittedValues [1] JWTClaimPermittedValuesList OPTIONAL
 * }
 *     -- If the claim name is present, the claim MUST contain one of
 *     -- the listed values.
 *   ( WITH COMPONENTS { ..., mustInclude PRESENT } |
 *   WITH COMPONENTS { ..., permittedValues PRESENT } )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimConstraints extends Asn1Encodable {

  private final JWTClaimNames mustInclude;

  private final JWTClaimPermittedValuesList permittedValues;

  public JWTClaimConstraints(JWTClaimNames mustInclude,
                             JWTClaimPermittedValuesList permittedValues) {
    if (mustInclude == null && permittedValues == null) {
      throw new IllegalArgumentException("mustInclude and permittedValues must no be both null");
    }
    this.mustInclude = mustInclude;
    this.permittedValues = permittedValues;
  }

  public JWTClaimNames getMustInclude() {
    return mustInclude;
  }

  public JWTClaimPermittedValuesList getPermittedValues() {
    return permittedValues;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        mustInclude == null ? null : Asn1TaggedObject.newExplicit(0, mustInclude),
        permittedValues == null ? null : Asn1TaggedObject.newExplicit(1, permittedValues));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (mustInclude != null) {
      mustInclude.toStringWithLineSep(buf, indentLevel, "mustInclude", true);
    }

    if (permittedValues != null) {
      permittedValues.toStringWithLineSep(buf, indentLevel, "permittedValues", true);
    }

    return deleteLastNewLine(buf);
  }

  public static JWTClaimConstraints fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);

    int index = 0;
    JWTClaimNames mustInclude = seq.isNotTaggedAt(index, 0) ? null
        : JWTClaimNames.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    JWTClaimPermittedValuesList permittedValues = seq.isNotTaggedAt(index, 1) ? null
        : JWTClaimPermittedValuesList.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);

    return new JWTClaimConstraints(mustInclude, permittedValues);
  }

}
