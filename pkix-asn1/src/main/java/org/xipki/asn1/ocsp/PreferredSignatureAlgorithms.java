// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 6960:
 * <pre>
 * id-pkix-ocsp-pref-sig-algs OBJECT IDENTIFIER ::= { id-pkix-ocsp 8 }
 *
 * PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PreferredSignatureAlgorithms extends PreferredSignatureAlgorithm.Seq0 {

  public PreferredSignatureAlgorithms(PreferredSignatureAlgorithm... entries) {
    super(entries);
  }

  public PreferredSignatureAlgorithms(List<PreferredSignatureAlgorithm> entries) {
    super(entries);
  }

  private PreferredSignatureAlgorithms(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PreferredSignatureAlgorithms fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PreferredSignatureAlgorithms(seq);
  }

  public static PreferredSignatureAlgorithms fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

}
