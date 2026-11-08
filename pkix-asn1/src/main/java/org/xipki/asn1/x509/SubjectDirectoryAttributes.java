// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectDirectoryAttributes extends Attribute.Seq1 {

  public SubjectDirectoryAttributes(Attribute... entries) {
    super(entries);
  }

  public SubjectDirectoryAttributes(List<Attribute> entries) {
    super(entries);
  }

  protected SubjectDirectoryAttributes(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static SubjectDirectoryAttributes fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SubjectDirectoryAttributes fromAsn1(Asn1Sequence set) throws CodecException {
    return new SubjectDirectoryAttributes(set);
  }

}
