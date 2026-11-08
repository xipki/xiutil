// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>: OriginatorInfo object.
 * <pre>
 * RFC 3369:
 *
 * OriginatorInfo ::= SEQUENCE {
 *     certs [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls  [1] IMPLICIT CertificateRevocationLists OPTIONAL
 * }
 *
 * CertificateSet ::= SET OF CertificateChoices
 * CertificateRevocationLists ::= SET OF CertificateList (from X.509)
 *
 * RFC 3582 / 5652:
 *
 * OriginatorInfo ::= SEQUENCE {
 *     certs [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls  [1] IMPLICIT RevocationInfoChoices OPTIONAL
 * }
 * </pre>
 * <p>
 *
 * @author Lijun Liao (xipki)
 */
public class OriginatorInfo extends Asn1Encodable {

  private final CertificateChoice.Set0 certs;
  private final RevocationInfoChoice.Set0 crls;

  public OriginatorInfo(CertificateChoice.Set0 certs, RevocationInfoChoice.Set0 crls) {
    this.certs = certs;
    this.crls  = crls;
  }

  public static OriginatorInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);

    int index = 0;
    CertificateChoice.Set0 certs = seq.isNotTaggedAt(index, 0) ? null
        : CertificateChoice.Set0.fromAsn1(seq.getSetTaggedAt(index++, false));
    RevocationInfoChoice.Set0 crls = seq.isNotTaggedAt(index, 1) ? null
        : RevocationInfoChoice.Set0.fromAsn1(seq.getSetTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new OriginatorInfo(certs, crls);
  }

  public boolean hasV2AttributeCertificate() {
    return certs != null && certs.hasV2AttributeCertificate();
  }

  public boolean hasOtherCertificate() {
    return certs != null && certs.hasOtherCertificate();
  }

  public boolean hasOtherCrl() {
    return crls != null && crls.hasOtherCrl();
  }

  public CertificateChoice.Set0 getCerts() {
    return certs;
  }

  public RevocationInfoChoice.Set0 getCrls() {
    return crls;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        (certs == null) ? null : Asn1TaggedObject.newImplicit(0, certs),
        (crls  == null) ? null : Asn1TaggedObject.newImplicit(1, crls));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (certs != null) {
      certs.toStringWithLineSep(buf, indentLevel, "certs", true);
    }

    if (crls != null) {
      crls.toStringWithLineSep(buf, indentLevel, "crls", true);
    }

    return deleteLastNewLine(buf);
  }
}
