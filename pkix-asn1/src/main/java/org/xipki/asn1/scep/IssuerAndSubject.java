// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.scep;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Issuer And Subject.
 *
 * @author Lijun Liao (xipki)
 */
public class IssuerAndSubject extends Asn1Encodable {

  private final X500Name issuer;

  private final X500Name subject;

  public static IssuerAndSubject fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static IssuerAndSubject fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.notNull(seq, "seq");
    return new IssuerAndSubject(X500Name.fromAsn1(seq.getSequenceAt(0)),
        X500Name.fromAsn1(seq.getSequenceAt(1)));
  }

  public IssuerAndSubject(X500Name issuer, X500Name subject) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.subject = Args.notNull(subject, "subject");
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public X500Name getSubject() {
    return subject;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(issuer, subject);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuer.toStringNoLineSep(buf, indentLevel, "issuer", true);
    subject.toStringNoLineSep(buf, indentLevel, "subject", true);

    return deleteLastNewLine(buf);
  }

}
