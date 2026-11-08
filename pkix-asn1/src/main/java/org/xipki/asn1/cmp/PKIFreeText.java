// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Utf8StringSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
 *          -- text encoded as UTF-8 String [RFC3629] (note: each
 *          -- UTF8String MAY include an [RFC3066] language tag
 *          -- to indicate the language of the contained text
 *          -- see [RFC2482] for details)
 *
 * @author Lijun Liao (xipki)
 */
public class PKIFreeText extends Utf8StringSeq {

  public PKIFreeText(String... entries) {
    super(1, entries);
  }

  public PKIFreeText(Asn1Utf8String... entries) {
    super(1, entries);
  }

  public PKIFreeText(List<Asn1Utf8String> entries) {
    super(1, entries);
  }

  private PKIFreeText(Asn1Sequence seq) throws CodecException {
    super(1, seq);
  }

  public static PKIFreeText fromAsn1(Asn1Sequence seq) throws CodecException {
    return new PKIFreeText(seq);
  }

  public String getStringAt(int i) {
    Asn1Utf8String utf8 = entries.get(i);
    return utf8 == null ? null : utf8.getString();
  }

}
