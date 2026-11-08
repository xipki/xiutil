// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class SubjectInfoAccessSyntax extends AccessDescription.Seq1 {

  public SubjectInfoAccessSyntax(AccessDescription... entries) {
    super(entries);
  }

  public SubjectInfoAccessSyntax(List<AccessDescription> entries) {
    super(entries);
  }

  private SubjectInfoAccessSyntax(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static SubjectInfoAccessSyntax fromAsn1(Asn1Sequence seq) throws CodecException {
    return new SubjectInfoAccessSyntax(seq);
  }

  public static SubjectInfoAccessSyntax fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

}
