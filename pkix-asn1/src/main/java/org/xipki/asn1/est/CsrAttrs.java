// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.est;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7030:
 * <pre>
 * CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CsrAttrs extends AttrOrOID.Seq0 {

  public CsrAttrs(AttrOrOID... entries) {
    super(entries);
  }

  public CsrAttrs(List<AttrOrOID> entries) {
    super(entries);
  }

  protected CsrAttrs(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static CsrAttrs fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CsrAttrs fromAsn1(Asn1Sequence seq) throws CodecException {
    return new CsrAttrs(seq);
  }

}
