// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;
import java.util.List;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * SingleResponse ::= SEQUENCE {
 *     certID                 CertID,
 *     certStatus             CertStatus,
 *     thisUpdate             GeneralizedTime,
 *     nextUpdate         [0] EXPLICIT GeneralizedTime OPTIONAL,
 *     singleExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SingleResponse extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<SingleResponse> {

    public Seq0(SingleResponse... entries) {
      super(entries);
    }

    public Seq0(List<SingleResponse> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected SingleResponse newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return SingleResponse.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final CertID  certID;
  private final OcspCertStatus certStatus;
  private final Asn1GeneralizedTime thisUpdate;
  private final Asn1GeneralizedTime nextUpdate;
  private final Extensions singleExtensions;

  public SingleResponse(CertID certID, OcspCertStatus certStatus, Asn1GeneralizedTime thisUpdate,
                        Asn1GeneralizedTime nextUpdate, Extensions  singleExtensions) {
    this.certID = Args.notNull(certID, "certID");
    this.certStatus = Args.notNull(certStatus, "certStatus");
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = nextUpdate;
    this.singleExtensions = singleExtensions;
  }

  public static SingleResponse fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq" , 3, 5);

    CertID certID = CertID.fromAsn1(seq.getSequenceAt(0));
    OcspCertStatus certStatus = OcspCertStatus.fromAsn1(seq.getTaggedAt(1));
    Asn1GeneralizedTime thisUpdate = seq.getGeneralizedTimeAt(2);

    int index = 3;
    Asn1GeneralizedTime nextUpdate = seq.isNotTaggedAt(index, 0) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, true);

    Extensions singleExtensions = seq.isNotTaggedAt(index, 1) ? null
        : Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    return new SingleResponse(certID, certStatus, thisUpdate, nextUpdate, singleExtensions);
  }

  public CertID getCertID() {
    return certID;
  }

  public OcspCertStatus getCertStatus() {
    return certStatus;
  }

  public Asn1GeneralizedTime getThisUpdate() {
    return thisUpdate;
  }

  public Asn1GeneralizedTime getNextUpdate() {
    return nextUpdate;
  }

  public Extensions getSingleExtensions() {
    return singleExtensions;
  }

  public Instant thisUpdate() {
    return thisUpdate.getTime();
  }

  public Instant nextUpdate() {
    return Asn1Util.fromAsn1(nextUpdate);
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return singleExtensions == null ? null : singleExtensions.getExtension(extensionId);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certID, certStatus, thisUpdate,
        (nextUpdate == null) ? null : Asn1TaggedObject.newExplicit(0, nextUpdate),
        (singleExtensions == null) ? null : Asn1TaggedObject.newExplicit(1, singleExtensions));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certID.toStringWithLineSep(buf, indentLevel, "certID", true);
    certStatus.toStringWithLineSep(buf, indentLevel, "certStatus", true);
    thisUpdate.toStringNoLineSep(buf, indentLevel, "thisUpdate", true);

    if (nextUpdate != null) {
      nextUpdate.toStringNoLineSep(buf, indentLevel, "nextUpdate", true);
    }

    if (singleExtensions != null) {
      singleExtensions.toStringWithLineSep(buf, indentLevel, "singleExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
