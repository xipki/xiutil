// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * PasswordRecipientInfo ::= SEQUENCE {
 *     version                    CMSVersion,   -- Always set to 0
 *     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
 *     keyEncryptionAlgorithm     KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey               EncryptedKey }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PasswordRecipientInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final AlgorithmIdentifier keyDerivationAlgorithm;
  private final AlgorithmIdentifier keyEncryptionAlgorithm;
  private final Asn1OctetString encryptedKey;

  public PasswordRecipientInfo(
      AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey) {
    this(null, keyEncryptionAlgorithm, encryptedKey);
  }

  public PasswordRecipientInfo(
      AlgorithmIdentifier keyDerivationAlgorithm,
      AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKey) {
    this(keyDerivationAlgorithm, keyEncryptionAlgorithm, Asn1Util.toOctetString(encryptedKey));
  }

  public PasswordRecipientInfo(
      AlgorithmIdentifier keyDerivationAlgorithm,
      AlgorithmIdentifier keyEncryptionAlgorithm, Asn1OctetString encryptedKey) {
    this.version = Asn1Integer.ZERO;
    this.keyDerivationAlgorithm = keyDerivationAlgorithm;
    this.keyEncryptionAlgorithm = Args.notNull(keyEncryptionAlgorithm, "keyEncryptionAlgorithm");
    this.encryptedKey = Args.notNull(encryptedKey, "encryptedKey");
  }

  public static PasswordRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 4);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(0)) {
      throw new CodecException("invalid version " + version);
    }

    int index = 1;
    AlgorithmIdentifier keyDerivationAlgorithm = seq.isNotTaggedAt(index, 0) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, false));
    AlgorithmIdentifier keyEncryptionAlgorithm =
        AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));
    Asn1OctetString encryptedKey = seq.getOctetStringAt(index++);

    Asn1Util.checkSequenceEnd(index, size);
    return new PasswordRecipientInfo(keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public AlgorithmIdentifier getKeyDerivationAlgorithm() {
  return keyDerivationAlgorithm;
  }

  public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
    return keyEncryptionAlgorithm;
  }

  public Asn1OctetString getEncryptedKey() {
    return encryptedKey;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] encryptedKey() {
    return encryptedKey.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version,
        keyDerivationAlgorithm == null ? null
            : Asn1TaggedObject.newImplicit(0, keyDerivationAlgorithm),
        keyEncryptionAlgorithm, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    if (keyDerivationAlgorithm != null) {
      keyDerivationAlgorithm.toStringWithLineSep(buf, indentLevel, "keyDerivationAlgorithm", true);
    }

    keyEncryptionAlgorithm.toStringWithLineSep(buf, indentLevel, "keyEncryptionAlgorithm", true);
    encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey", true);

    return deleteLastNewLine(buf);
  }

}
