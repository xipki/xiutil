// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.spdm;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * id-spdm-cert-oids ::= SEQUENCE SIZE (1..MAX) OF id-spdm-cert-oid
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SpdmCertOids extends SpdmCertOid.Seq1 {

  public SpdmCertOids(SpdmCertOid... entries) {
    super(entries);
  }

  public SpdmCertOids(List<SpdmCertOid> entries) {
    super(entries);
  }

  protected SpdmCertOids(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static SpdmCertOids fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SpdmCertOids fromAsn1(Asn1Sequence seq) throws CodecException {
    return new SpdmCertOids(seq);
  }

}
