// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * PBMParameter ::= SEQUENCE {
 *     salt                OCTET STRING,
 *          -- note:  implementations MAY wish to limit acceptable sizes
 *          -- of this string to values appropriate for their environment
 *          -- in order to reduce the risk of denial-of-service attacks
 *     owf                 AlgorithmIdentifier,
 *          -- AlgId for a One-Way Function (SHA-1 recommended)
 *     iterationCount      INTEGER,
 *          -- number of times the OWF is applied
 *          -- note:  implementations MAY wish to limit acceptable sizes
 *          -- of this integer to values appropriate for their environment
 *          -- in order to reduce the risk of denial-of-service attacks
 *     mac                 AlgorithmIdentifier
 *          -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 * }   -- or HMAC [RFC2104, RFC2202])
 *
 * @author Lijun Liao (xipki)
 */
public class PBMParameter extends Asn1Encodable {

  private final Asn1OctetString salt;
  private final AlgorithmIdentifier owf;
  private final Asn1Integer iterationCount;
  private final AlgorithmIdentifier mac;

  public static PBMParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 4);
    Asn1OctetString salt = seq.getOctetStringAt(0);
    AlgorithmIdentifier owf = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1Integer iterationCount = seq.getNonNegativeIntegerAt(2);
    BigInteger iterationCountValue = iterationCount.getValue();
    if (iterationCountValue.signum() <= 0 || iterationCountValue.bitLength() > 31) {
      throw new CodecException("invalid iterationCount " + iterationCountValue);
    }
    AlgorithmIdentifier mac = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(3));
    return new PBMParameter(salt, owf, iterationCount, mac);
  }

  public PBMParameter(byte[] salt, AlgorithmIdentifier owf,
                      int iterationCount, AlgorithmIdentifier mac) {
    this.salt = new Asn1OctetString(Args.notNull(salt, "salt"));
    this.owf = Args.notNull(owf, "ows");
    this.iterationCount = new Asn1Integer(iterationCount);
    this.mac = Args.notNull(mac, "mac");
  }

  public PBMParameter(Asn1OctetString salt, AlgorithmIdentifier owf,
                      Asn1Integer iterationCount, AlgorithmIdentifier mac) {
    this.salt = Args.notNull(salt, "salt");
    this.owf = Args.notNull(owf, "ows");
    this.iterationCount = Args.notNull(iterationCount, "iterationCount");
    this.mac = Args.notNull(mac, "mac");
  }

  public Asn1OctetString getSalt() {
    return salt;
  }

  public AlgorithmIdentifier getOwf() {
    return owf;
  }

  public Asn1Integer getIterationCount() {
    return iterationCount;
  }

  public AlgorithmIdentifier getMac()   {
    return mac;
  }

  public byte[] salt() {
    return salt.getOctets();
  }

  public int iterationCount() {
    return iterationCount.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(salt, owf, iterationCount, mac);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    salt.toStringWithLineSep(buf, indentLevel, "salt", true);
    owf.toStringWithLineSep(buf, indentLevel, "owf", true);
    iterationCount.toStringNoLineSep(buf, indentLevel, "iterationCount", true);
    mac.toStringWithLineSep(buf, indentLevel, "mac", true);

    return deleteLastNewLine(buf);
  }

}
