// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PolicyMappings V3 extension, described in RFC3280.
 * <pre>
 *    PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 * </pre>
 *
 * @see <a href="https://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a>
 *
 * @author Lijun Liao (xipki)
 */
public class PolicyMappings extends PolicyMapping.Seq1 {

  public PolicyMappings(PolicyMapping... entries) {
    super(entries);
  }

  public PolicyMappings(List<PolicyMapping> entries) {
    super(entries);
  }

  protected PolicyMappings(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PolicyMappings fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PolicyMappings fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PolicyMappings(seq);
  }

}
