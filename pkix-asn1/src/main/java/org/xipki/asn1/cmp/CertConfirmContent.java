// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * CertConfirmContent ::= SEQUENCE OF CertStatus
 *
 * @author Lijun Liao (xipki)
 */
public class CertConfirmContent extends CmpCertStatus.Seq0 {

  public CertConfirmContent(CmpCertStatus... entries) {
    super(entries);
  }

  public CertConfirmContent(List<CmpCertStatus> entries) {
    super(entries);
  }

  private CertConfirmContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static CertConfirmContent fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertConfirmContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new CertConfirmContent(seq);
  }

}
