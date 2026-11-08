// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public class BiometricSyntax extends BiometricData.Seq0 {

  public BiometricSyntax(BiometricData... entries) {
    super(entries);
  }

  public BiometricSyntax(List<BiometricData> entries) {
    super(entries);
  }

  protected BiometricSyntax(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static BiometricSyntax fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static BiometricSyntax fromAsn1(Asn1Sequence seq) throws CodecException {
    return new BiometricSyntax(seq);
  }

}
