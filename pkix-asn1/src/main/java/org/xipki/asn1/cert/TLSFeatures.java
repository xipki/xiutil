// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.IntegerSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7633
 * <pre>
 * Features ::= SEQUENCE OF INTEGER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TLSFeatures extends IntegerSeq {

  public TLSFeatures(int... entries) {
    super(0, entries);
  }

  private TLSFeatures(Asn1Integer... entries) {
    super(0, entries);
  }

  private TLSFeatures(Asn1Sequence seq) throws CodecException {
    super(0, seq);
  }

  public static TLSFeatures ofIntegers(List<Integer> value) {
    if (value == null || value.isEmpty()) {
      return new TLSFeatures((int[]) null);
    } else {
      return new TLSFeatures(toIntegersI(value));
    }
  }

  public static TLSFeatures fromAsn1(Asn1Sequence seq) throws CodecException {
    TLSFeatures features = new TLSFeatures(seq);
    // the features are TLS extension types (0..65535)
    for (Asn1Integer feature : features.getEntries()) {
      Asn1Integer.checkNonNegative(feature);
    }
    return features;
  }

  public static TLSFeatures fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

}
