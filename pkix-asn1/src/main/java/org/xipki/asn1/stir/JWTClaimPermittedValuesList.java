// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimPermittedValuesList ::= SEQUENCE SIZE (1..MAX) Of
 *                                       JWTClaimPermittedValues
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimPermittedValuesList extends JWTClaimPermittedValues.Seq1 {

  public JWTClaimPermittedValuesList(JWTClaimPermittedValues... entries) {
    super(entries);
  }

  public JWTClaimPermittedValuesList(List<JWTClaimPermittedValues> entries) {
    super(entries);
  }

  protected JWTClaimPermittedValuesList(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static JWTClaimPermittedValuesList fromAsn1(Asn1Sequence seq) throws CodecException {
    return new JWTClaimPermittedValuesList(seq);
  }

}
