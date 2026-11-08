// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.stir;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TNAuthorizationList extends TNEntry.Seq1 {

  public TNAuthorizationList(TNEntry... entries) {
    super(entries);
  }

  public TNAuthorizationList(List<TNEntry> entries) {
    super(entries);
  }

  protected TNAuthorizationList(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static TNAuthorizationList fromAsn1(Asn1Sequence seq) throws CodecException {
    return new TNAuthorizationList(seq);
  }

  public static TNAuthorizationList fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

}
