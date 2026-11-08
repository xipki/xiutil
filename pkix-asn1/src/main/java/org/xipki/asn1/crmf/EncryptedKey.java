// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * EncryptedKey ::= CHOICE {
 *     encryptedValue        EncryptedValue, -- deprecated
 *     envelopedData     [0] EnvelopedData }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptedKey extends Asn1Encodable {

  private final EncryptedValue encryptedValue;
  private final EnvelopedData envelopedData;

  private EncryptedKey(EncryptedValue encryptedValue, EnvelopedData envelopedData) {
    this.encryptedValue = encryptedValue;
    this.envelopedData = envelopedData;
  }

  public static EncryptedKey ofEnvelopedData(EnvelopedData envelopedData) {
    return new EncryptedKey(null, Args.notNull(envelopedData, "envelopedData"));
  }

  public static EncryptedKey ofEncryptedKey(EncryptedValue encryptedValue) {
    return new EncryptedKey(Args.notNull(encryptedValue, "encryptedValue"), null);
  }

  public static EncryptedKey fromAsn1(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");

    EncryptedValue encryptedValue = null;
    EnvelopedData envelopedData = null;
    if (asn1 instanceof Asn1Sequence) {
      encryptedValue = EncryptedValue.fromAsn1((Asn1Sequence) asn1);
    } else if (asn1 instanceof Asn1TaggedObject && asn1.getTagNo() == 0) {
      envelopedData = EnvelopedData.fromAsn1(((Asn1TaggedObject) asn1).getImplicitSequenceBase());
    } else {
      throw new CodecException("invalid asn1 structure for EncryptedKey");
    }
    return new EncryptedKey(encryptedValue, envelopedData);
  }

  public Asn1Encodable getChoiceData() {
    return envelopedData != null ? envelopedData : encryptedValue;
  }

  public EncryptedValue getEncryptedValue() {
    return encryptedValue;
  }

  public EnvelopedData getEnvelopedData() {
    return envelopedData;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return encryptedValue != null ? encryptedValue.toAsn1Primitive()
        : Asn1TaggedObject.newImplicit(0, envelopedData);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (encryptedValue != null) {
      return encryptedValue.toStringWithLineSep(buf, indentLevel, "encryptedValue");
    }

    return envelopedData.toStringWithLineSep(buf, indentLevel, "envelopedData");
  }

}
