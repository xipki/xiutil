// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The following attributes has attribute value of type Traits defined in this class:
 * <ul>
 *   <li>PreviousPlatformCertificates</li>
 *   <li>cryptographicAnchors</li>
 *   <li>tBBSecurityAssertions</li>
 *   <li>ComponentIdentifier</li>
 *   <li>PlatformConfigUri-v3</li>
 *   <li>PlatformOwnership</li>
 * </ul>
 *
 * <pre>
 * Traits ::= SEQUENCE(SIZE(1..MAX) OF Trait
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Traits extends Trait.Seq1 {

  public Traits(Trait... entries) {
    super(entries);
  }

  public Traits(List<Trait> entries) {
    super(entries);
  }

  public Traits(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static Traits fromAsn1(Asn1Sequence seq) throws CodecException {
    return new Traits(seq);
  }

}
