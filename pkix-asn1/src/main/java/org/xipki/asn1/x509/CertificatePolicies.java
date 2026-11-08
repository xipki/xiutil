// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificatePolicies extends PolicyInformation.Seq1 {

  public CertificatePolicies(PolicyInformation... entries) {
    super(entries);
  }

  public CertificatePolicies(List<PolicyInformation> entries) {
    super(entries);
  }

  protected CertificatePolicies(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static CertificatePolicies fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertificatePolicies fromAsn1(Asn1Sequence seq) throws CodecException {
    return new CertificatePolicies(seq);
  }

}
