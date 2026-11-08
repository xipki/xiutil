// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class PdsLocations extends PdsLocation.Seq1 {

  public PdsLocations(PdsLocation... entries) {
    super(entries);
  }

  public PdsLocations(List<PdsLocation> entries) {
    super(entries);
  }

  private PdsLocations(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static PdsLocations fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PdsLocations fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PdsLocations(seq);
  }

}
