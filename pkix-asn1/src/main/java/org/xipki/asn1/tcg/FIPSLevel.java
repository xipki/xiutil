// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * FIPSLevel ::= SEQUENCE {
 *     version IA5String (SIZE (1..STRMAX)), -- “140-1”, “140-2”, or “140-3”
 *     level   SecurityLevel,
 *     plus    BOOLEAN DEFAULT FALSE
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class FIPSLevel extends Asn1Encodable {

  private final Asn1IA5String version;

  private final SecurityLevel level;

  private final boolean plus;

  public FIPSLevel(String version, SecurityLevel level, boolean plus) {
    this(Asn1Util.toIA5String(version), level, plus);
  }

  public FIPSLevel(Asn1IA5String version, SecurityLevel level, boolean plus) {
    this.version = Args.lengthRange(version, "version", 1, TcgConstants.STRMAX);
    this.level = Args.notNull(level, "level");
    this.plus = plus;
  }

  public Asn1IA5String getVersion() {
    return version;
  }

  public SecurityLevel getLevel() {
    return level;
  }

  public boolean isPlus() {
    return plus;
  }

  public String version() {
    return version.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, level,
        plus ? Asn1Boolean.TRUE : null);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    level.toStringNoLineSep(buf, indentLevel, "level", true);
    ToStringUtil.appendIndent(buf, indentLevel, "plus: " + plus + "\n");

    return deleteLastNewLine(buf);
  }

  public static FIPSLevel fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static FIPSLevel fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1IA5String version = seq.getIA5StringAt(0);
    SecurityLevel level = SecurityLevel.fromAsn1(seq.getEnumeratedAt(1));
    int index = 2;
    Asn1Boolean plus = seq.notHasBoolean(index) ? null : seq.getBooleanAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new FIPSLevel(version, level, plus != null && plus.isTrue());
  }

}
