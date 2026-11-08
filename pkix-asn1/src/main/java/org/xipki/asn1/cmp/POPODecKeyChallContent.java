// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * POPODecKeyChallContent ::= SEQUENCE OF Challenge
 * -- One Challenge per encryption key certification request (in the
 * -- same order as these requests appear in CertReqMessages).
 *
 * @author Lijun Liao (xipki)
 */
public class POPODecKeyChallContent extends Challenge.Seq0 {

  public POPODecKeyChallContent(Challenge... entries) {
    super(entries);
  }

  public POPODecKeyChallContent(List<Challenge> entries) {
    super(entries);
  }

  protected POPODecKeyChallContent(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static POPODecKeyChallContent fromAsn1(Asn1Sequence seq) throws CodecException {
    return new POPODecKeyChallContent(seq);
  }

}
