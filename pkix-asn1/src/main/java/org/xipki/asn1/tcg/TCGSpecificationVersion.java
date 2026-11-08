// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * tCGCredentialSpecification ATTRIBUTE ::= {
 *     WITH SYNTAX TCGSpecificationVersion
 *     ID tcg-at-tcgCredentialSpecification }
 *
 * TCGSpecificationVersion ::= SEQUENCE {
 *     majorVersion  INTEGER,
 *     minorVersion  INTEGER,
 *     revision      INTEGER }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGSpecificationVersion extends Asn1Encodable {

  private final Asn1Integer majorVersion;

  private final Asn1Integer minorVersion;

  private final Asn1Integer revision;

  public TCGSpecificationVersion(long majorVersion, long minorVersion, long revision) {
    this(Asn1Util.toInteger(majorVersion), Asn1Util.toInteger(minorVersion),
        Asn1Util.toInteger(revision));
  }

  public TCGSpecificationVersion(
      Asn1Integer majorVersion, Asn1Integer minorVersion, Asn1Integer revision) {
    this.majorVersion = Args.notNegative(majorVersion, "majorVersion");
    this.minorVersion = Args.notNegative(minorVersion, "minorVersion");
    this.revision     = Args.notNegative(revision, "revision");
  }

  public Asn1Integer getMajorVersion() {
    return majorVersion;
  }

  public Asn1Integer getMinorVersion() {
    return minorVersion;
  }

  public Asn1Integer getRevision() {
    return revision;
  }

  public int majorVersion() {
    return majorVersion.intValueExact();
  }

  public int minorVersion() {
    return minorVersion.intValueExact();
  }

  public int revision() {
    return revision.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(majorVersion, minorVersion, revision);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (majorVersion == null) {
      return buf;
    }

    String str = majorVersion.toString();
    if (minorVersion != null) {
      str += "." + minorVersion;
    }

    if (revision != null) {
      str += "." + revision;
    }

    return ToStringUtil.appendIndent(buf, indentLevel, str);
  }

  public static TCGSpecificationVersion fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    return new TCGSpecificationVersion(seq.getNonNegativeIntegerAt(0),
        seq.getNonNegativeIntegerAt(1), seq.getNonNegativeIntegerAt(2));
  }

}
