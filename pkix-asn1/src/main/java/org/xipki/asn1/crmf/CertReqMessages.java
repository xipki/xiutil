// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertReqMessages extends CertReqMsg.Seq1 {

  public CertReqMessages(CertReqMsg... entries) {
    super(entries);
  }

  public CertReqMessages(List<CertReqMsg> entries) {
    super(entries);
  }

  protected CertReqMessages(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static CertReqMessages fromAsn1(Asn1Sequence seq) throws CodecException {
    return new CertReqMessages(seq);
  }

}
