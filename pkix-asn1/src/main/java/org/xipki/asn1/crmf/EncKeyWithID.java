// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * EncKeyWithID ::= SEQUENCE {
 *     privateKey           PrivateKeyInfo,
 *     identifier CHOICE {
 *         string               UTF8String,
 *         generalName          GeneralName
 *     } OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncKeyWithID extends Asn1Encodable {

  private final PrivateKeyInfo privKeyInfo;
  private final Asn1Utf8String stringId;
  private final GeneralName generalNameId;

  public static EncKeyWithID fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    PrivateKeyInfo privKeyInfo = PrivateKeyInfo.fromAsn1(seq.getSequenceAt(0));

    Asn1Utf8String stringId = null;
    GeneralName generalNameId = null;
    if (size == 2) {
      Asn1Primitive p = seq.getObjectAt(1);
      if (p instanceof Asn1Utf8String) {
        stringId = (Asn1Utf8String) p;
      } else {
        generalNameId = GeneralName.fromAsn1(p.asTagged());
      }
    }

    if (stringId != null) {
      return new EncKeyWithID(privKeyInfo, stringId);
    } else if (generalNameId != null) {
      return new EncKeyWithID(privKeyInfo, generalNameId);
    } else {
      return new EncKeyWithID(privKeyInfo);
    }
  }

  public EncKeyWithID(PrivateKeyInfo privKeyInfo) {
    this.privKeyInfo = Args.notNull(privKeyInfo, "privKeyInfo");
    this.stringId = null;
    this.generalNameId = null;
  }

  public EncKeyWithID(PrivateKeyInfo privKeyInfo, Asn1Utf8String stringId) {
    this.privKeyInfo = Args.notNull(privKeyInfo, "privKeyInfo");
    this.stringId = stringId;
    this.generalNameId = null;
  }

  public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalNameId) {
    this.privKeyInfo = Args.notNull(privKeyInfo, "privKeyInfo");
    this.stringId = null;
    this.generalNameId = generalNameId;
  }

  public PrivateKeyInfo getPrivKeyInfo() {
    return privKeyInfo;
  }

  public Asn1Utf8String getStringId() {
    return stringId;
  }

  public GeneralName getGeneralNameId() {
    return generalNameId;
  }

  public PrivateKeyInfo getPrivateKey() {
    return privKeyInfo;
  }

  public String stringId() {
    return Asn1Util.fromAsn1(stringId);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(privKeyInfo,
        stringId != null ? stringId : generalNameId);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    privKeyInfo.toStringWithLineSep(buf, indentLevel, "privKeyInfo", true);

    if (stringId != null) {
      stringId.toStringNoLineSep(buf, indentLevel, "stringId", true);
    }

    if (generalNameId != null) {
      generalNameId.toStringWithLineSep(buf, indentLevel, "generalNameId", true);
    }

    return deleteLastNewLine(buf);
  }

}
