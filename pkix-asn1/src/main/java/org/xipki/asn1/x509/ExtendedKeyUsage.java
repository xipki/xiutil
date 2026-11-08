// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.OidSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The extendedKeyUsage object.
 * <pre>
 *  extendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ExtendedKeyUsage extends OidSeq {

  public ExtendedKeyUsage(Asn1Oid... entries) {
    super(1, entries);
  }

  public ExtendedKeyUsage(List<Asn1Oid> entries) {
    super(1, entries);
  }

  private ExtendedKeyUsage(Asn1Sequence seq) throws CodecException {
    super(1, seq);
  }

  public static ExtendedKeyUsage fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ExtendedKeyUsage fromAsn1(Asn1Sequence seq) throws CodecException {
    return new ExtendedKeyUsage(seq);
  }

  public boolean hasKeyPurposeId(Asn1Oid keyPurposeId) {
    return entries.contains(keyPurposeId);
  }

}
