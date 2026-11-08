// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * GeneralSubtrees ::= SEQUENCE SIZE {1..MAX} OF GeneralSubtree
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralSubtrees extends GeneralSubtree.Seq1 {

  public GeneralSubtrees(GeneralSubtree... entries) {
    super(entries);
  }

  public GeneralSubtrees(List<GeneralSubtree> entries) {
    super(entries);
  }

  private GeneralSubtrees(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static GeneralSubtrees fromAsn1(Asn1Sequence seq) throws CodecException {
    return new GeneralSubtrees(seq);
  }

}
