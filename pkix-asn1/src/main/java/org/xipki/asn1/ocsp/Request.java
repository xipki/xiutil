// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * Request         ::=     SEQUENCE {
 *     reqCert                  CertID,
 *     singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Request extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<Request> {

    public Seq0(Request... entries) {
      super(entries);
    }

    public Seq0(List<Request> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected Request newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Request.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final CertID reqCert;
  private final Extensions singleRequestExtensions;

  public Request(CertID reqCert, Extensions singleRequestExtensions) {
    this.reqCert = Args.notNull(reqCert, "reqCert");
    this.singleRequestExtensions = singleRequestExtensions;
  }

  public static Request fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    CertID reqCert = CertID.fromAsn1(seq.getSequenceAt(0));
    Extensions singleRequestExtensions = (size == 1) ? null
        : Extensions.fromAsn1(seq.getTaggedAt(1, 0).getExplicitSequenceBase());
    return new Request(reqCert, singleRequestExtensions);
  }

  public CertID getReqCert() {
    return reqCert;
  }

  public Extensions getSingleRequestExtensions() {
    return singleRequestExtensions;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(reqCert,
        (singleRequestExtensions == null) ? null
            : Asn1TaggedObject.newExplicit(0, singleRequestExtensions));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    reqCert.toStringWithLineSep(buf, indentLevel, "reqCert", true);

    if (singleRequestExtensions != null) {
      singleRequestExtensions.toStringWithLineSep(buf, indentLevel,
          "singleRequestExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
