// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.asn1.cms.ContentInfo;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC7292 (PKCS#12):
 * <pre>
 * PFX ::= SEQUENCE {
 *     version     INTEGER {v3(3)}(v3,...),
 *     authSafe    ContentInfo,
 *     macData     MacData OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Pfx extends Asn1Encodable {

  private final ContentInfo contentInfo;
  private final MacData macData;

  public static Pfx fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static Pfx fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);

    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(3)) {
      throw new IllegalArgumentException("wrong version for PFX PDU: " + version);
    }

    ContentInfo contentInfo = ContentInfo.fromAsn1(seq.getSequenceAt(1));
    MacData macData = (size > 2) ? MacData.fromAsn1(seq.getSequenceAt(2)) : null;
    return new Pfx(contentInfo, macData);
  }

  public Pfx(ContentInfo contentInfo, MacData macData) {
    this.contentInfo = Args.notNull(contentInfo, "contentInfo");
    this.macData = macData;
  }

  public ContentInfo getAuthSafe() {
    return contentInfo;
  }

  public MacData getMacData() {
    return macData;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(Asn1Integer.THREE, contentInfo, macData);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    contentInfo.toStringWithLineSep(buf, indentLevel, "contentInfo", true);

    if (macData != null) {
      macData.toStringWithLineSep(buf, indentLevel, "macData", true);
    }

    return deleteLastNewLine(buf);
  }

}
