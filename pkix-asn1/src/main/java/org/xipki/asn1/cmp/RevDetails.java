// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertTemplate;
import org.xipki.asn1.x509.Extensions;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * RevDetails ::= SEQUENCE {
 *   certDetails         CertTemplate,
 *          -- allows requester to specify as much as they can about
 *          -- the cert. for which revocation is requested
 *          -- (e.g., for cases in which serialNumber is not available)
 *   crlEntryDetails     Extensions       OPTIONAL
 *          -- requested crlEntryExtensions
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RevDetails extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<RevDetails> {

    public Seq0(RevDetails... entries) {
      super(entries);
    }

    public Seq0(List<RevDetails> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected RevDetails newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return RevDetails.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final CertTemplate certDetails;
  private final Extensions crlEntryDetails;

  public static RevDetails fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    CertTemplate certDetails = CertTemplate.fromAsn1(seq.getSequenceAt(0));
    Extensions crlEntryDetails = (size == 1) ? null : Extensions.fromAsn1(seq.getSequenceAt(1));
    return new RevDetails(certDetails, crlEntryDetails);
  }

  public RevDetails(CertTemplate certDetails) {
    this(certDetails, null);
  }

  public RevDetails(CertTemplate certDetails, Extensions crlEntryDetails) {
    this.certDetails = Args.notNull(certDetails, "certDetails");
    this.crlEntryDetails = crlEntryDetails;
  }

  public CertTemplate getCertDetails() {
    return certDetails;
  }

  public Extensions getCrlEntryDetails() {
    return crlEntryDetails;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certDetails, crlEntryDetails);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certDetails.toStringWithLineSep(buf, indentLevel, "certDetails", true);

    if (crlEntryDetails != null) {
      crlEntryDetails.toStringWithLineSep(buf, indentLevel, "crlEntryDetails", true);
    }

    return deleteLastNewLine(buf);
  }
}
