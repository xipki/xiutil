// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Extensions;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * TBSRequest      ::=     SEQUENCE {
 *     version             [0] EXPLICIT Version DEFAULT v1,
 *     requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *     requestList                      SEQUENCE OF Request,
 *     requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TBSRequest extends Asn1Encodable {

  private static final Asn1Integer V1 = Asn1Integer.ZERO;

  private final Asn1Integer version;
  private final GeneralName requestorName;
  private final Request.Seq0 requestList;
  private final Extensions  requestExtensions;

  public TBSRequest(GeneralName requestorName, Request.Seq0 requestList,
                    Extensions requestExtensions) {
    this(V1, requestorName, requestList, requestExtensions);
  }

  public TBSRequest(Asn1Integer version, GeneralName requestorName, Request.Seq0 requestList,
                    Extensions requestExtensions) {
    this.version = Args.notNull(version, "version");
    this.requestorName = requestorName;
    this.requestList = Args.notNull(requestList, "requestList");
    this.requestExtensions = requestExtensions;
  }

  public static TBSRequest fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 4);
    int index = 0;

    Asn1Integer version = !seq.isTaggedAt(index, 0) ? V1
        : seq.getNonNegativeIntegerTaggedAt(index++, true);
    GeneralName requestorName = seq.isNotTaggedAt(index, 1) ? null
        : GeneralName.fromAsn1(seq.getTaggedAt(index++).getExplicitTaggedBase());
    Request.Seq0 requestList = Request.Seq0.fromAsn1(seq.getSequenceAt(index++));
    Extensions requestExtensions = seq.isTaggedAt(index, 2)
        ? Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, true)) : null;

    Asn1Util.checkSequenceEnd(index, size);
    return new TBSRequest(version, requestorName, requestList, requestExtensions);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public GeneralName getRequestorName() {
    return requestorName;
  }

  public Request.Seq0 getRequestList() {
    return requestList;
  }

  public Extensions getRequestExtensions() {
    return requestExtensions;
  }

  public int version() {
    return version.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        (version == null || V1.equals(version) ? null : Asn1TaggedObject.newExplicit(0, version)),
        (requestorName == null ? null : Asn1TaggedObject.newExplicit(1, requestorName)),
        requestList,
        (requestExtensions == null ? null : Asn1TaggedObject.newExplicit(2, requestExtensions)));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);

    if (requestorName != null) {
      requestorName.toStringWithLineSep(buf, indentLevel, "requestorName", true);
    }

    requestList.toStringWithLineSep(buf, indentLevel, "requestList", true);

    if (requestExtensions != null) {
      requestExtensions.toStringWithLineSep(buf, indentLevel, "requestExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
