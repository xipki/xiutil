// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * ASIdentifier Choice.
 *
 * <pre>
 *    ASIdentifierChoice  ::= CHOICE {
 *       inherit              NULL, -- inherit from issuer --
 *       asIdsOrRanges        SEQUENCE OF ASIdOrRange }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ASIdentifierChoice extends Asn1Encodable {

  private static final ASIdentifierChoice INHERIT = new ASIdentifierChoice(null);

  private final ASIdOrRange.Seq0 asIdsOrRanges;

  private ASIdentifierChoice(ASIdOrRange.Seq0 asIdsOrRanges) {
    this.asIdsOrRanges = asIdsOrRanges;
  }

  public static ASIdentifierChoice ofInherit() {
    return INHERIT;
  }

  public static ASIdentifierChoice ofAsIdsOrRanges(ASIdOrRange.Seq0 asIdsOrRanges) {
    return new ASIdentifierChoice(Args.notNull(asIdsOrRanges, "asIdsOrRanges"));
  }

  public static ASIdentifierChoice fromAsn1(Asn1Primitive asn1) throws CodecException {
    return (asn1 instanceof Asn1Null) ? ofInherit()
        : ofAsIdsOrRanges(ASIdOrRange.Seq0.fromAsn1(asn1.asSequence()));
  }

  public ASIdOrRange.Seq0 getAsIdsOrRanges() {
    return asIdsOrRanges;
  }

  public boolean isInherit() {
    return asIdsOrRanges == null;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return asIdsOrRanges == null ? Asn1Null.INSTANCE : asIdsOrRanges.toAsn1Primitive();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (isInherit()) {
      return ToStringUtil.appendIndent(buf, indentLevel, "inherit");
    } else {
      return asIdsOrRanges.toStringWithLineSep(buf, indentLevel, "asIdsOrRanges");
    }
  }
}
