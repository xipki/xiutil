// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * GeneralNames ::= SEQUENCE SIZE {1..MAX} OF GeneralName
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralNames extends GeneralName.Seq1 {

  public GeneralNames(GeneralName... names) {
    super(names);
  }

  public GeneralNames(List<GeneralName> names) {
    super(names);
  }

  private GeneralNames(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static GeneralNames fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static GeneralNames fromAsn1(Asn1Sequence seq) throws CodecException {
    return new GeneralNames(seq);
  }

}
