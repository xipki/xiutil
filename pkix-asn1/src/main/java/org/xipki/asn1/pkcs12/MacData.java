// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.DigestInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 7292:
 * <pre>
 * MacData ::= SEQUENCE {
 *     mac        DigestInfo,
 *     macSalt    OCTET STRING,
 *     iterations INTEGER DEFAULT 1
 *     -- Note: The default is for historic reasons and its use is deprecated. A
 *     -- higher value, like 1024 is recommended.
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class MacData extends Asn1Encodable {

  private final DigestInfo digInfo;
  private final Asn1OctetString macSalt;
  private final Asn1Integer iterations;

  public static MacData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    DigestInfo digInfo = DigestInfo.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString macSalt = seq.getOctetStringAt(1);
    Asn1Integer iterations = (size == 2) ? Asn1Integer.ONE : seq.getNonNegativeIntegerAt(2);
    return new MacData(digInfo, macSalt, iterations);
  }

  public MacData(DigestInfo digInfo, Asn1OctetString macSalt, Asn1Integer iterations) {
    this.digInfo = Args.notNull(digInfo, "digInfo");
    this.macSalt = Args.notNull(macSalt, "macSalt");
    this.iterations = Args.notNull(iterations, "iterations");
  }

  public MacData(DigestInfo digInfo, byte[] macSalt, int iterations) {
    this(digInfo, Asn1Util.toOctetString(macSalt), new Asn1Integer(iterations));
  }

  public DigestInfo getMac() {
    return digInfo;
  }

  public Asn1OctetString getMacSalt() {
    return macSalt;
  }

  public Asn1Integer getIterations() {
    return iterations;
  }

  public byte[] macSalt() {
    return macSalt.getOctets();
  }

  public int iterations() {
    return iterations.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(digInfo, macSalt,
        iterations.equals(Asn1Integer.ONE) ? null : iterations);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    digInfo.toStringWithLineSep(buf, indentLevel, "digInfo", true);
    macSalt.toStringWithLineSep(buf, indentLevel, "macSalt", true);
    iterations.toStringNoLineSep(buf, indentLevel, "iterations", true);

    return deleteLastNewLine(buf);
  }
}
