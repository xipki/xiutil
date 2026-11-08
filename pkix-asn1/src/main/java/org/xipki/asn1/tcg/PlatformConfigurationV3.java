// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * PlatformConfiguration-v3 ::= SEQUENCE {
 *     platformComponents [0] IMPLICIT SEQUENCE(SIZE(1..MAX)) OF ComponentIdentifier-v2 OPTIONAL,
 *     platformProperties [1] IMPLICIT SEQUENCE(SIZE(1..MAX)) OF Property OPTIONAL }
 *
 * ComponentIdentifier-v2 ::= SEQUENCE(SIZE(1..MAX)) OF Trait
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformConfigurationV3 extends Asn1Encodable {

  private final Traits platformComponents;

  private final Properties platformProperties;

  public PlatformConfigurationV3(Traits platformComponents, Properties platformProperties) {
    if (platformComponents == null && platformProperties == null) {
      throw new IllegalArgumentException(
          "platformComponents and platformProperties must not be both null");
    }
    this.platformComponents = platformComponents;
    this.platformProperties = platformProperties;
  }

  public Traits getPlatformComponents() {
    return platformComponents;
  }

  public Properties getPlatformProperties() {
    return platformProperties;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        (platformComponents == null) ? null : Asn1TaggedObject.newImplicit(0, platformComponents),
        (platformProperties == null) ? null : Asn1TaggedObject.newImplicit(1, platformProperties));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (platformComponents != null) {
      platformComponents.toStringWithLineSep(buf, indentLevel, "platformComponents", true);
    }

    if (platformProperties != null) {
      platformProperties.toStringWithLineSep(buf, indentLevel, "platformProperties", true);
    }

    return deleteLastNewLine(buf);
  }

  public static PlatformConfigurationV3 fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;
    Traits components = seq.isNotTaggedAt(index, 0) ? null
        : Traits.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Properties properties = seq.isNotTaggedAt(index, 1) ? null
        : Properties.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    Asn1Util.checkSequenceEnd(index, size);
    return new PlatformConfigurationV3(components, properties);
  }

}
