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
 * <a href="https://tools.ietf.org/html/rfc5940">RFC 5940</a>:
 * Additional Cryptographic Message Syntax (CMS) Revocation Information Choices.
 * <p>
 * <pre>
 * SCVPReqRes ::= SEQUENCE {
 *     request  [0] EXPLICIT ContentInfo OPTIONAL,
 *     response     ContentInfo }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SCVPReqRes extends Asn1Encodable {

  private final ContentInfo request;
  private final ContentInfo response;

  public static SCVPReqRes fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);

    int index = 0;
    ContentInfo request = seq.isNotTaggedAt(index, 0) ? null
        : ContentInfo.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    ContentInfo response = ContentInfo.fromAsn1(seq.getSequenceAt(index++));
    Asn1Util.checkSequenceEnd(index, size);
    return new SCVPReqRes(request, response);
  }

  public SCVPReqRes(ContentInfo request, ContentInfo response) {
    this.request = request;
    this.response = Args.notNull(response, "response");
  }

  public ContentInfo getRequest() {
    return request;
  }

  public ContentInfo getResponse() {
    return response;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        request == null ? null : Asn1TaggedObject.newExplicit(0, request),
        response);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (request != null) {
      request.toStringWithLineSep(buf, indentLevel, "request", true);
    }

    response.toStringWithLineSep(buf, indentLevel, "response", true);

    return deleteLastNewLine(buf);
  }
}
