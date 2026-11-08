// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The AuthorityInformationAccess object.
 * <pre>
 * AuthorityInfoAccessSyntax  ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AuthorityInfoAccessSyntax extends AccessDescription.Seq1 {

  public AuthorityInfoAccessSyntax(AccessDescription... entries) {
    super(entries);
  }

  public AuthorityInfoAccessSyntax(List<AccessDescription> entries) {
    super(entries);
  }

  protected AuthorityInfoAccessSyntax(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static AuthorityInfoAccessSyntax fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AuthorityInfoAccessSyntax fromAsn1(Asn1Sequence seq) throws CodecException {
    return new AuthorityInfoAccessSyntax(seq);
  }

}
