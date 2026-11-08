// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 7292:
 * <pre>
 * pkcs-12PbeParams ::= SEQUENCE {
 *     salt        OCTET STRING,
 *     iterations  INTEGER
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKCS12PBEParams extends Asn1Encodable {

  private final Asn1OctetString salt;
  private final Asn1Integer iterations;

  public PKCS12PBEParams(byte[] salt, int iterations) {
    this.salt = new Asn1OctetString(Args.notNull(salt, "salt"));
    this.iterations = new Asn1Integer(iterations);
  }

  public PKCS12PBEParams(Asn1OctetString salt, Asn1Integer iterations) {
    this.salt = Args.notNull(salt, "salt");
    this.iterations = Args.notNull(iterations, "iterations");
  }

  public static PKCS12PBEParams fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1OctetString salt = seq.getOctetStringAt(0);
    Asn1Integer iterations = seq.getNonNegativeIntegerAt(1);
    return new PKCS12PBEParams(salt, iterations);
  }

  public Asn1Integer getIterations() {
    return iterations;
  }

  public Asn1OctetString getSalt()
  {
      return salt;
  }

  public int iterations() {
    return iterations.intValueExact();
  }

  public byte[] salt()
  {
      return salt.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(salt, iterations);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    salt.toStringWithLineSep(buf, indentLevel, "salt", true);
    iterations.toStringNoLineSep(buf, indentLevel, "iterations", true);

    return deleteLastNewLine(buf);
  }

}
