// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;

/**
 * <pre>
 * CRLEntry ::= SEQUENCE {
 *     userCertificate         CertificateSerialNumber,
 *     revocationDate          Time,
 *     crlEntryExtensions      Extensions OPTIONAL
 *                             -- if present, shall be v2
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CRLEntry extends Asn1Encodable {

  private final Asn1Integer userCertificate;

  private final Time revocationDate;

  private final Extensions crlEntryExtensions;

  public static CRLEntry fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer userCertificate = seq.getNonNegativeIntegerAt(0);
    Time revocationDate = Time.fromAsn1(seq.getTimeAt(1));
    Extensions crlEntryExtensions = (size == 2) ? null
        : Extensions.fromAsn1(seq.getSequenceAt(2));
    return new CRLEntry(userCertificate, revocationDate, crlEntryExtensions);
  }

  public CRLEntry(Asn1Integer userCertificate, Time revocationDate, Extensions crlEntryExtensions) {
    this.userCertificate = Args.notNull(userCertificate, "userCertificate");
    this.revocationDate = Args.notNull(revocationDate, "revocationDate");
    this.crlEntryExtensions = crlEntryExtensions;
  }

  public CRLEntry(BigInteger userCertificate, Instant revocationDate,
                  Extensions crlEntryExtensions) {
    this.userCertificate = new Asn1Integer(Args.notNull(userCertificate, "userCertificate"));
    this.revocationDate = new Time(Args.notNull(revocationDate, "revocationDate"));
    this.crlEntryExtensions = crlEntryExtensions;
  }

  public Asn1Integer getUserCertificate() {
    return userCertificate;
  }

  public Time getRevocationDate() {
    return revocationDate;
  }

  public Extensions getExtensions() {
    return crlEntryExtensions;
  }

  public BigInteger userCertificate() {
    return userCertificate.getValue();
  }

  public Instant revocationDate() {
    return revocationDate.time();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(userCertificate, revocationDate, crlEntryExtensions);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    userCertificate.toStringNoLineSep(buf, indentLevel, "userCertificate", true);
    revocationDate.toStringNoLineSep(buf, indentLevel, "revocationDate", true);

    if (crlEntryExtensions != null) {
      crlEntryExtensions.toStringWithLineSep(buf, indentLevel, "crlEntryExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
