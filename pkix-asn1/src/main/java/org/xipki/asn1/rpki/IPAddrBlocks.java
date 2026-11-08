// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.rpki;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * IPAddr Blocks.
 * <pre>
 * IPAddrBlocks        ::= SEQUENCE OF IPAddressFamily
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddrBlocks extends Asn1IPAddressFamily.Seq0 {

  public IPAddrBlocks(Asn1IPAddressFamily... entries) {
    super(entries);
  }

  public IPAddrBlocks(List<Asn1IPAddressFamily> entries) {
    super(entries);
  }

  private IPAddrBlocks(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static IPAddrBlocks fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static IPAddrBlocks fromAsn1(Asn1Sequence seq) throws CodecException {
    return new IPAddrBlocks(seq);
  }

}
