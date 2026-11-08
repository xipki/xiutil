// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.IA5StringSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimNames ::= SEQUENCE SIZE (1..MAX) OF JWTClaimName
 *
 * JWTClaimName ::= IA5String
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimNames extends IA5StringSeq {

  public JWTClaimNames(Asn1IA5String... entries) {
    super(1, entries);
  }

  public JWTClaimNames(List<Asn1IA5String> entries) {
    super(1, entries);
  }

  public JWTClaimNames(String... entries) {
    super(1, Asn1Util.toIA5Strings(entries));
  }

  public JWTClaimNames(Asn1Sequence seq) throws CodecException {
    super(1, seq);
  }

  public static JWTClaimNames fromAsn1(Asn1Sequence seq) throws CodecException {
    return new JWTClaimNames(seq);
  }

}
