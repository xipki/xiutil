// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * DHBMParameter ::= SEQUENCE {
 *     owf   AlgorithmIdentifier,
 *           -- AlgId for a One-Way Function (SHA-1 recommended)
 *     mac   AlgorithmIdentifier
 *           -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 * }   -- or HMAC [RFC2104, RFC2202])
 *
 * @author Lijun Liao (xipki)
 */
public class DHBMParameter extends Asn1Encodable {

  private final AlgorithmIdentifier owf;
  private final AlgorithmIdentifier mac;

  public static DHBMParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);

    AlgorithmIdentifier owf = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier mac = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    return new DHBMParameter(owf, mac);
  }

  public DHBMParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac) {
    this.owf = Args.notNull(owf, "owf");
    this.mac = Args.notNull(mac, "mac");
  }

  public AlgorithmIdentifier getOwf() {
    return owf;
  }

  public AlgorithmIdentifier getMac() {
    return mac;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(owf, mac);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    owf.toStringWithLineSep(buf, indentLevel, "owf", true);
    mac.toStringWithLineSep(buf, indentLevel, "mac", true);

    return deleteLastNewLine(buf);
  }
}
