// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * OriginComposition SEQUENCE ::= Sequence {
 *     location      EntityGeoLocation,
 *     hasComponents [0] BOOLEAN DEFAULT TRUE OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OriginComposition extends Asn1Encodable {

  private final EntityGeoLocation location;

  private final boolean hasComponents;

  public OriginComposition(EntityGeoLocation location, boolean hasComponents) {
    this.location = Args.notNull(location, "location");
    this.hasComponents = hasComponents;
  }

  public EntityGeoLocation getLocation() {
    return location;
  }

  public boolean hasComponents() {
    return hasComponents;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(location, hasComponents ? null : Asn1Boolean.FALSE);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    location.toStringWithLineSep(buf, indentLevel, "location", true);
    ToStringUtil.appendIndent(buf, indentLevel, "hasComponents: " + hasComponents + "\n");

    return deleteLastNewLine(buf);
  }

  public static OriginComposition fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    EntityGeoLocation location = EntityGeoLocation.fromAsn1(seq.getSequenceAt(0));
    int index = 1;
    boolean hasComponents = seq.notHasBoolean(index) || seq.getBooleanAt(index++).isTrue();
    Asn1Util.checkSequenceEnd(index, size);
    return new OriginComposition(location, hasComponents);
  }

}
