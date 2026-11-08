// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * OCSPResponse ::= SEQUENCE {
 *     responseStatus         OCSPResponseStatus,
 *     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 * </pre>
 * @see OCSPResponseStatus
 * @see ResponseBytes
 *
 * @author Lijun Liao (xipki)
 */
public class OCSPResponse extends Asn1Encodable {

  private final OCSPResponseStatus responseStatus;
  private final ResponseBytes responseBytes;

  public OCSPResponse(OCSPResponseStatus responseStatus, ResponseBytes responseBytes) {
    this.responseStatus = Args.notNull(responseStatus, "responseStatus");
    this.responseBytes = responseBytes;
  }

  public static OCSPResponse fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static OCSPResponse fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    OCSPResponseStatus responseStatus = OCSPResponseStatus.getInstance(
        seq.getEnumeratedAt(0).getValue());
    ResponseBytes responseBytes = (size == 1) ? null :
        ResponseBytes.fromAsn1(seq.getTaggedAt(1, 0).getExplicitSequenceBase());
    return new OCSPResponse(responseStatus, responseBytes);
  }

  public OCSPResponseStatus getResponseStatus() {
    return responseStatus;
  }

  public ResponseBytes getResponseBytes() {
    return responseBytes;
  }

  public BasicOCSPResponse getBasicOCSPResponse() {
    return responseBytes.getBasicOCSPResponse();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(responseStatus,
        (responseBytes == null ? null : Asn1TaggedObject.newExplicit(0, responseBytes)));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    responseStatus.toStringNoLineSep(buf, indentLevel, "responseStatus", true);

    if (responseBytes != null) {
      responseBytes.toStringWithLineSep(buf, indentLevel, "responseBytes", true);
    }

    return deleteLastNewLine(buf);
  }

}
