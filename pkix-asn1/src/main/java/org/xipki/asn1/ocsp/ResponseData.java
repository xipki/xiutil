// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1,
 *     responderID              ResponderID,
 *     producedAt               GeneralizedTime,
 *     responses                SEQUENCE OF SingleResponse,
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ResponseData extends Asn1Encodable {

  private static final Asn1Integer V1 = Asn1Integer.ZERO;

  private final Asn1Integer version;
  private final ResponderID responderID;
  private final Asn1GeneralizedTime producedAt;
  private final SingleResponse.Seq0 responses;
  private final Extensions responseExtensions;

  public ResponseData(Asn1Integer version, ResponderID responderID, Asn1GeneralizedTime producedAt,
                      SingleResponse.Seq0 responses, Extensions responseExtensions) {
    this.version = Args.notNull(version, "version");
    this.responderID = Args.notNull(responderID, "responderID");
    this.producedAt = Args.notNull(producedAt, "producedAt");
    this.responses = Args.notNull(responses, "responses");
    this.responseExtensions = responseExtensions;
  }

  public ResponseData(ResponderID responderID, Asn1GeneralizedTime producedAt,
                      SingleResponse.Seq0 responses, Extensions responseExtensions) {
    this(V1, responderID, producedAt, responses, responseExtensions);
  }

  public static ResponseData fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ResponseData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 5);
    int index = 0;

    Asn1Integer version = seq.isNotTaggedAt(index, 0) ? V1
        : seq.getNonNegativeIntegerTaggedAt(index++, true);
    ResponderID responderID = ResponderID.fromAsn1(seq.getTaggedAt(index++));
    Asn1GeneralizedTime producedAt = seq.getGeneralizedTimeAt(index++);
    SingleResponse.Seq0 responses = SingleResponse.Seq0.fromAsn1(seq.getSequenceAt(index++));
    Extensions responseExtensions = seq.isNotTaggedAt(index, 1) ? null
        : Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    Asn1Util.checkSequenceEnd(index, size);
    return new ResponseData(version, responderID, producedAt, responses, responseExtensions);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public ResponderID getResponderID() {
    return responderID;
  }

  public Asn1GeneralizedTime getProducedAt() {
    return producedAt;
  }

  public SingleResponse.Seq0 getResponses() {
    return responses;
  }

  public Extensions getResponseExtensions() {
    return responseExtensions;
  }

  public int version() {
    return version.intValueExact();
  }

  public Instant producedAt() {
    return producedAt.getTime();
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return responseExtensions == null ? null : responseExtensions.getExtension(extensionId);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        version == null || version.equals(V1) ? null
            : Asn1TaggedObject.newExplicit(0, version),
        responderID, producedAt, responses,
        (responseExtensions == null) ? null
            : Asn1TaggedObject.newExplicit(1, responseExtensions));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    responderID.toStringWithLineSep(buf, indentLevel, "responderID", true);
    producedAt.toStringNoLineSep(buf, indentLevel, "producedAt", true);
    responses.toStringWithLineSep(buf, indentLevel, "responses", true);

    if (responseExtensions != null) {
      responseExtensions.toStringWithLineSep(buf, indentLevel, "responseExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
