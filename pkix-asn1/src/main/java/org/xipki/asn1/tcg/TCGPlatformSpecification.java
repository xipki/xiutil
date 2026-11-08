// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * tCGPlatformSpecification ATTRIBUTE ::= {
 *     WITH SYNTAX TCGPlatformSpecification
 *     ID tcg-at-tcgPlatformSpecification }
 *
 * TCGPlatformSpecification ::= SEQUENCE {
 *     version TCGSpecificationVersion,
 *     platformClass OCTET STRING (SIZE(4)) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGPlatformSpecification extends Asn1Encodable {

  private final TCGSpecificationVersion version;

  private final Asn1OctetString platformClass;

  public TCGPlatformSpecification(TCGSpecificationVersion version, byte[] platformClass) {
    this(version, Asn1Util.toOctetString(platformClass));
  }

  public TCGPlatformSpecification(TCGSpecificationVersion version, Asn1OctetString platformClass) {
    this.version = Args.notNull(version, "version");
    this.platformClass = Args.notNull(platformClass, "platformClass");
    Args.equals(platformClass.getOctetsLength(), "platformClass.length", 4);
  }

  public TCGSpecificationVersion getVersion() {
    return version;
  }

  public Asn1OctetString getPlatformClass() {
    return platformClass;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, platformClass);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    platformClass.toStringWithLineSep(buf, indentLevel, "platformClass", true);

    return deleteLastNewLine(buf);
  }

  public static TCGPlatformSpecification fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new TCGPlatformSpecification(
          TCGSpecificationVersion.fromAsn1(seq.getSequenceAt(0)),
          seq.getOctetStringAt(1));
  }

}
