// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertId;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 * RevAnnContent ::= SEQUENCE {
 *     status              PKIStatus,
 *     certId              CertId,
 *     willBeRevokedAt     GeneralizedTime,
 *     badSinceDate        GeneralizedTime,
 *     crlDetails          Extensions  OPTIONAL
 *     -- extra CRL details (e.g., crl number, reason, location, etc.)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevAnnContent extends Asn1Encodable {

  private final PKIStatus status;
  private final CertId certId;
  private final Asn1GeneralizedTime willBeRevokedAt;
  private final Asn1GeneralizedTime badSinceDate;
  private final Extensions crlDetails;

  public RevAnnContent(
      PKIStatus status, CertId certId, Asn1GeneralizedTime willBeRevokedAt,
      Asn1GeneralizedTime badSinceDate) {
      this(status, certId, willBeRevokedAt, badSinceDate, null);
  }

  public RevAnnContent(
      PKIStatus status, CertId certId, Asn1GeneralizedTime willBeRevokedAt,
      Asn1GeneralizedTime badSinceDate, Extensions crlDetails) {
    this.status = Args.notNull(status, "status");
    this.certId = Args.notNull(certId, "certId");
    this.willBeRevokedAt = Args.notNull(willBeRevokedAt, "willBeRevokedAt");
    this.badSinceDate = Args.notNull(badSinceDate, "badSinceDate");
    this.crlDetails = crlDetails;
  }

  public static RevAnnContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 4, 5);
    Asn1Integer iStatus = seq.getNonNegativeIntegerAt(0);
    PKIStatus status = PKIStatus.getInstance(iStatus.intValueExact());
    CertId certId = CertId.fromAsn1(seq.getSequenceAt(1));
    Asn1GeneralizedTime willBeRevokedAt = seq.getGeneralizedTimeAt(2);
    Asn1GeneralizedTime badSinceDate = seq.getGeneralizedTimeAt(3);
    Extensions crlDetails = (size == 4) ? null : Extensions.fromAsn1(seq.getSequenceAt(4));
    return new RevAnnContent(status, certId, willBeRevokedAt, badSinceDate, crlDetails);
  }

  public PKIStatus getStatus() {
    return status;
  }

  public CertId getCertId() {
    return certId;
  }

  public Asn1GeneralizedTime getWillBeRevokedAt() {
    return willBeRevokedAt;
  }

  public Asn1GeneralizedTime getBadSinceDate() {
    return badSinceDate;
  }

  public Extensions getCrlDetails() {
    return crlDetails;
  }

  public Instant willBeRevokedAt() {
    return willBeRevokedAt.getTime();
  }

  public Instant badSinceDate() {
    return badSinceDate.getTime();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(status, certId, willBeRevokedAt, badSinceDate, crlDetails);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    status.toStringNoLineSep(buf, indentLevel, "status", true);
    certId.toStringWithLineSep(buf, indentLevel, "certId", true);
    willBeRevokedAt.toStringNoLineSep(buf, indentLevel, "willBeRevokedAt", true);
    badSinceDate.toStringNoLineSep(buf, indentLevel, "badSinceDate", true);

    if (crlDetails != null) {
      crlDetails.toStringWithLineSep(buf, indentLevel, "crlDetails", true);
    }

    return deleteLastNewLine(buf);
  }

}
