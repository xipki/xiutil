// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7292:
 * <pre>
 * SafeContents ::= SEQUENCE OF SafeBag
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SafeContents extends SafeBag.Seq0 {

  public SafeContents(SafeBag... entries) {
    super(entries);
  }

  public SafeContents(List<SafeBag> entries) {
    super(entries);
  }

  private SafeContents(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static SafeContents fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SafeContents fromAsn1(Asn1Sequence seq) throws CodecException {
    return new SafeContents(seq);
  }

}
