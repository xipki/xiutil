// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ccc;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * xxx ::= SEQUENCE {
 *    version INTEGER
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SimpleExtensionSchema extends Asn1Encodable {

  private final Asn1Integer version;

  public SimpleExtensionSchema(Asn1Integer version) {
    this.version = Args.notNull(version, "version");
  }

  public SimpleExtensionSchema(int version) {
    this.version = new Asn1Integer(version);
  }

  public static SimpleExtensionSchema fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SimpleExtensionSchema fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 1);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    return new SimpleExtensionSchema(version);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public int version() {
    return version.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return version.toStringNoLineSep(buf, indentLevel, "version", false);
  }
}
