// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 4211:
 * <pre>
 * (IMPLICIT TAGS)
 * EncryptedValue ::= SEQUENCE {
 *     intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
 *                   -- the intended algorithm for which the value will be used
 *     symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
 *                   -- the symmetric algorithm used to encrypt the value
 *     encSymmKey    [2] BIT STRING           OPTIONAL,
 *                    -- the (encrypted) symmetric key used to encrypt the value
 *     keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
 *                   -- algorithm used to encrypt the symmetric key
 *     valueHint     [4] OCTET STRING         OPTIONAL,
 *                   -- a brief description or identifier of the encValue content
 *                   -- (may be meaningful only to the sending entity, and used only
 *                   -- if EncryptedValue might be re-examined by the sending entity
 *                   -- in the future)
 *     encValue      BIT STRING }
 *                   -- the encrypted value itself
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptedValue extends Asn1Encodable {

  private final AlgorithmIdentifier intendedAlg;
  private final AlgorithmIdentifier symmAlg;
  private final Asn1BitString       encSymmKey;
  private final AlgorithmIdentifier keyAlg;
  private final Asn1OctetString     valueHint;
  private final Asn1BitString       encValue;

  public static EncryptedValue fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 6);
    int index = 0;
    // intendedAlg;
    AlgorithmIdentifier intendedAlg = seq.isNotTaggedAt(index, 0) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    // symmAlg;
    AlgorithmIdentifier symmAlg = seq.isNotTaggedAt(index, 1) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    // encSymmKey;
    Asn1BitString encSymmKey = seq.isNotTaggedAt(index, 2) ? null
        : seq.getBitStringTaggedAt(index++, false);

    // keyAlg;
    AlgorithmIdentifier keyAlg = seq.isNotTaggedAt(index, 3) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    // valueHint;
    Asn1OctetString valueHint = seq.isNotTaggedAt(index, 4) ? null
        : seq.getOctetStringTaggedAt(index++, false);

    Asn1Util.checkSequenceEnd(index, size - 1);

    // encValue;
    Asn1BitString encValue = seq.getBitStringAt(size - 1);
    return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
  }

  public EncryptedValue(
      AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, Asn1BitString encSymmKey,
      AlgorithmIdentifier keyAlg, Asn1OctetString valueHint, Asn1BitString encValue) {
    this.intendedAlg = intendedAlg;
    this.symmAlg = symmAlg;
    this.encSymmKey = encSymmKey;
    this.keyAlg = keyAlg;
    this.valueHint = valueHint;
    this.encValue = Args.notNull(encValue, "encValue");
  }

  public AlgorithmIdentifier getIntendedAlg() {
    return intendedAlg;
  }

  public AlgorithmIdentifier getSymmAlg() {
    return symmAlg;
  }

  public Asn1BitString getEncSymmKey() {
    return encSymmKey;
  }

  public AlgorithmIdentifier getKeyAlg() {
    return keyAlg;
  }

  public Asn1OctetString getValueHint() {
    return valueHint;
  }

  public Asn1BitString getEncValue() {
    return encValue;
  }

  public byte[] encSymmKey() {
    return Asn1Util.fromAsn1(encSymmKey);
  }

  public byte[] valueHint() {
    return Asn1Util.fromAsn1(valueHint);
  }

  public byte[] encValue() {
    return encValue.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        intendedAlg == null ? null : Asn1TaggedObject.newImplicit(0, intendedAlg),
        symmAlg == null ? null : Asn1TaggedObject.newImplicit(1, symmAlg),
        encSymmKey == null ? null : Asn1TaggedObject.newImplicit(2, encSymmKey),
        keyAlg == null ? null : Asn1TaggedObject.newImplicit(3, keyAlg),
        valueHint == null ? null : Asn1TaggedObject.newImplicit(4, valueHint),
        encValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (intendedAlg != null) {
      intendedAlg.toStringWithLineSep(buf, indentLevel, "intendedAlg", true);
    }

    if (symmAlg != null) {
      symmAlg.toStringWithLineSep(buf, indentLevel, "symmAlg", true);
    }

    if (encSymmKey != null) {
      encSymmKey.toStringWithLineSep(buf, indentLevel, "encSymmKey", true);
    }

    if (keyAlg != null) {
      keyAlg.toStringWithLineSep(buf, indentLevel, "keyAlg", true);
    }

    if (valueHint != null) {
      valueHint.toStringWithLineSep(buf, indentLevel, "valueHint", true);
    }

    encValue.toStringWithLineSep(buf, indentLevel, "encValue", true);

    return deleteLastNewLine(buf);
  }
}
