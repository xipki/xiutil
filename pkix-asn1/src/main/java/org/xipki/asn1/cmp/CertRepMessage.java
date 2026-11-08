// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * CertRepMessage ::= SEQUENCE {
 *   caPubs    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
 *   response      SEQUENCE OF CertResponse
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertRepMessage extends Asn1Encodable {

  private final CMPCertificate.Seq1 caPubs;
  private final CertResponse.Seq0 response;

  public static CertRepMessage fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertRepMessage fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;
    CMPCertificate.Seq1 caPubs = seq.isNotTaggedAt(index, 1) ? null
        : CMPCertificate.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    CertResponse.Seq0 response = CertResponse.Seq0.fromAsn1(seq.getSequenceAt(index++));
    Asn1Util.checkSequenceEnd(index, size);
    return new CertRepMessage(caPubs, response);
  }

  public CertRepMessage(CMPCertificate.Seq1 caPubs, CertResponse.Seq0 response) {
    this.caPubs = caPubs;
    this.response = Args.notNull(response, "response");
  }

  public CMPCertificate.Seq1 getCaPubs() {
    return caPubs;
  }

  public CertResponse.Seq0 getResponse() {
    return response;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        caPubs == null ? null : Asn1TaggedObject.newExplicit(1, caPubs),
        response);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (caPubs != null) {
      caPubs.toStringWithLineSep(buf, indentLevel, "caPubs", true);
    }

    return response.toStringWithLineSep(buf, indentLevel, "response");
  }
}
