// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * PKIX RFC 5280
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
 *
 * PolicyConstraints ::= SEQUENCE {
 *      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PolicyConstraints extends Asn1Encodable {

  private final Asn1Integer requireExplicitPolicyMapping;
  private final Asn1Integer inhibitPolicyMapping;

  public PolicyConstraints(BigInteger requireExplicitPolicyMapping,
                           BigInteger inhibitPolicyMapping) {
    this.requireExplicitPolicyMapping = Asn1Util.toInteger(requireExplicitPolicyMapping);
    this.inhibitPolicyMapping = Asn1Util.toInteger(inhibitPolicyMapping);
  }

  public PolicyConstraints(Asn1Integer requireExplicitPolicyMapping,
                           Asn1Integer inhibitPolicyMapping) {
    this.requireExplicitPolicyMapping = requireExplicitPolicyMapping;
    this.inhibitPolicyMapping = inhibitPolicyMapping;
    if (requireExplicitPolicyMapping != null) {
      Args.notNegative(requireExplicitPolicyMapping.getValue(), "requireExplicitPolicyMapping");
    }

    if (inhibitPolicyMapping != null) {
      Args.notNegative(inhibitPolicyMapping.getValue(), "inhibitPolicyMapping");
    }
  }

  public static PolicyConstraints fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PolicyConstraints fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.notNull(seq, "seq").size();
    int index = 0;
    Asn1Integer requireExplicitPolicyMapping = seq.isNotTaggedAt(index, 0) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    Asn1Integer inhibitPolicyMapping = seq.isNotTaggedAt(index, 1) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, false);
    Asn1Util.checkSequenceEnd(index, size);
    return new PolicyConstraints(requireExplicitPolicyMapping, inhibitPolicyMapping);
  }

  public Asn1Integer getRequireExplicitPolicyMapping() {
    return requireExplicitPolicyMapping;
  }

  public Asn1Integer getInhibitPolicyMapping() {
    return inhibitPolicyMapping;
  }

  public Integer requireExplicitPolicyMapping() {
    return Asn1Util.fromAsn1Int(requireExplicitPolicyMapping);
  }

  public Integer inhibitPolicyMapping() {
    return Asn1Util.fromAsn1Int(inhibitPolicyMapping);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        requireExplicitPolicyMapping == null ? null
            : Asn1TaggedObject.newImplicit(0, requireExplicitPolicyMapping),
        inhibitPolicyMapping == null ? null
            : Asn1TaggedObject.newImplicit(1, inhibitPolicyMapping));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (requireExplicitPolicyMapping != null) {
      requireExplicitPolicyMapping.toStringNoLineSep(buf, indentLevel,
          "requireExplicitPolicyMapping");
    }

    if (inhibitPolicyMapping != null) {
      if (requireExplicitPolicyMapping != null) {
        buf.append("\n");
      }
      inhibitPolicyMapping.toStringNoLineSep(buf, indentLevel, "inhibitPolicyMapping");
    }
    return buf;
  }
}
