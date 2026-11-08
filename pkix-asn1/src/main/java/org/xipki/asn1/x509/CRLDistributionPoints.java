// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * CRLDistributionPoints ::= SEQUENCE SIZE {1..MAX} OF DistributionPoint
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CRLDistributionPoints extends DistributionPoint.Seq1 {

  public CRLDistributionPoints(DistributionPoint... entries) {
    super(entries);
  }

  public CRLDistributionPoints(List<DistributionPoint> entries) {
    super(entries);
  }

  private CRLDistributionPoints(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static CRLDistributionPoints fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CRLDistributionPoints fromAsn1(Asn1Sequence seq) throws CodecException {
    return new CRLDistributionPoints(seq);
  }

}
