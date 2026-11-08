// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Boolean;
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
 * BasicConstraints := SEQUENCE {
 *    cA                  BOOLEAN DEFAULT FALSE,
 *    pathLenConstraint   INTEGER (0..MAX) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class BasicConstraints extends Asn1Encodable {

  private final boolean cA;
  private final Asn1Integer pathLenConstraint;

  public static BasicConstraints fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static BasicConstraints fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);
    int index = 0;
    boolean cA = seq.notHasBoolean(index) ? false : seq.getBooleanAt(index++).isTrue();
    Asn1Integer pathLenConstraint = seq.notHasInteger(index)
        ? null : seq.getNonNegativeIntegerAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new BasicConstraints(cA, pathLenConstraint);
  }

  public BasicConstraints(boolean cA) {
    this.cA = cA;
    this.pathLenConstraint = null;
  }

  public BasicConstraints(int pathLenConstraint) {
    this.cA = true;
    this.pathLenConstraint = new Asn1Integer(pathLenConstraint);
  }

  public BasicConstraints(boolean cA, Asn1Integer pathLenConstraint) {
    this.cA = cA;
    this.pathLenConstraint = pathLenConstraint;
  }

  public boolean isCA() {
    return cA;
  }

  public Asn1Integer getPathLenConstraint() {
    return pathLenConstraint;
  }

  public Integer pathLenConstraint() {
    return Asn1Util.fromAsn1Int(pathLenConstraint);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(cA ? Asn1Boolean.TRUE : null, pathLenConstraint);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "CA: " + cA).append("\n");
    if (pathLenConstraint != null) {
      pathLenConstraint.toStringNoLineSep(buf, indentLevel, "pathLenConstraint", true);
    }
    return deleteLastNewLine(buf);
  }
}
