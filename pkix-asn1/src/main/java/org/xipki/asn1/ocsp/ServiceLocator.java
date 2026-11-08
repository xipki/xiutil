// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.AuthorityInfoAccessSyntax;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * ServiceLocator ::= SEQUENCE {
 *     issuer    Name,
 *     locator   AuthorityInfoAccessSyntax OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ServiceLocator extends Asn1Encodable {

  private final X500Name issuer;
  private final AuthorityInfoAccessSyntax locator;

  public ServiceLocator(X500Name issuer, AuthorityInfoAccessSyntax locator) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.locator = locator;
  }

  public static ServiceLocator fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    X500Name issuer = X500Name.fromAsn1(seq.getSequenceAt(0));
    AuthorityInfoAccessSyntax locator = (size == 1) ? null
        : AuthorityInfoAccessSyntax.fromAsn1(seq.getSequenceAt(1));
    return new ServiceLocator(issuer, locator);
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public AuthorityInfoAccessSyntax getLocator() {
    return locator;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(issuer, locator);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    issuer.toStringNoLineSep(buf, indentLevel, "issuer", true);

    if (locator != null) {
      locator.toStringWithLineSep(buf, indentLevel, "locator", true);
    }

    return deleteLastNewLine(buf);
  }

}
