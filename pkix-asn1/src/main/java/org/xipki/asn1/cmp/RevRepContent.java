// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertId;
import org.xipki.asn1.x509.CertificateList;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.LinkedList;
import java.util.List;

/**
 * <pre>
 * RevRepContent ::= SEQUENCE {
 *     status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
 *          -- in same order as was sent in RevReqContent
 *     revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
 *          -- IDs for which revocation was requested
 *          -- (same order as status)
 *     crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
 *          -- the resulting CRLs (there may be more than one)
 * }
 *</pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevRepContent extends Asn1Encodable {

  public static class Builder {

    private final List<PKIStatusInfo> status = new LinkedList<>();
    private final List<CertId> revCerts = new LinkedList<>();
    private final List<CertificateList> crls = new LinkedList<>();

    public Builder add(PKIStatusInfo status) {
      this.status.add(status);
      return this;
    }

    public Builder add(PKIStatusInfo status, CertId certId) {
      if (this.status.size() != this.revCerts.size()) {
        throw new IllegalStateException("status and revCerts sequence must be in common order");
      }
      this.status.add(status);
      this.revCerts.add(certId);

      return this;
    }

    public Builder addCrl(CertificateList crl) {
      this.crls.add(crl);
      return this;
    }

    public RevRepContent build() {
      CertId.Seq1 revCerts = this.revCerts.isEmpty() ? null
          : new CertId.Seq1(this.revCerts.toArray(new CertId[0]));
      CertificateList.Seq1 crls = this.crls.isEmpty() ? null
          : new CertificateList.Seq1(this.crls.toArray(new CertificateList[0]));

      return new RevRepContent(new PKIStatusInfo.Seq1(status.toArray(new PKIStatusInfo[0])),
          revCerts, crls);
    }

  }

  private final PKIStatusInfo.Seq1 status;
  private final CertId.Seq1 revCerts;
  private final CertificateList.Seq1 crls;

  public static RevRepContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    PKIStatusInfo.Seq1 status = PKIStatusInfo.Seq1.fromAsn1(seq.getSequenceAt(0));
    int index = 1;
    CertId.Seq1 revCerts = seq.isNotTaggedAt(index, 0) ? null
        : CertId.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    CertificateList.Seq1 crls = seq.isNotTaggedAt(index, 1) ? null
        : CertificateList.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    Asn1Util.checkSequenceEnd(index, size);
    return new RevRepContent(status, revCerts, crls);
  }

  public RevRepContent(PKIStatusInfo.Seq1 status, CertId.Seq1 revCerts, CertificateList.Seq1 crls) {
    this.status = Args.notNull(status, "status");
    this.revCerts = revCerts;
    this.crls = crls;
  }

  public PKIStatusInfo.Seq1 getStatus() {
    return status;
  }

  public CertId.Seq1 getRevCerts() {
    return revCerts;
  }

  public CertificateList.Seq1 getCrls() {
    return crls;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(status,
        revCerts == null ? null : Asn1TaggedObject.newExplicit(0, revCerts),
        crls     == null ? null : Asn1TaggedObject.newExplicit(1, crls));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    status.toStringWithLineSep(buf, indentLevel, "status", true);

    if (revCerts != null) {
      revCerts.toStringWithLineSep(buf, indentLevel, "revCerts", true);
    }

    if (crls != null) {
      crls.toStringWithLineSep(buf, indentLevel, "crls", true);
    }

    return deleteLastNewLine(buf);
  }

}
