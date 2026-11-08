// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.OidSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * ETSI EN 319 412-5:
 * <pre>
 * QcType::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER
 *   (id-etsi-qct-esign | id-etsi-qct-eseal |
 *     id-etsi-qct-web | ...)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class QcType extends OidSeq {

  public QcType(Asn1Oid... entries) {
    super(1, entries);
  }

  public QcType(List<Asn1Oid> entries) {
    super(1, entries);
  }

  protected QcType(Asn1Sequence seq) throws CodecException {
    super(1, seq);
  }

  public static QcType fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static QcType fromAsn1(Asn1Sequence seq) throws CodecException {
    return new QcType(seq);
  }

}
