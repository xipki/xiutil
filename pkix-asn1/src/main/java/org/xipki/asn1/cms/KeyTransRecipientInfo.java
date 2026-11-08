// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * KeyTransRecipientInfo ::= SEQUENCE {
 *     version                 CMSVersion,  -- always set to 0 or 2
 *     rid                     RecipientIdentifier,
 *     keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey            EncryptedKey
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KeyTransRecipientInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final RecipientIdentifier rid;
  private final AlgorithmIdentifier keyEncryptionAlgorithm;
  private final Asn1OctetString encryptedKey;

  public KeyTransRecipientInfo(
      RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm,
      Asn1OctetString encryptedKey) {
    this(new Asn1Integer(Args.notNull(rid, "rid").getIssuerAndSerialNumber() != null ? 0 : 2),
        rid, keyEncryptionAlgorithm, encryptedKey);
  }

  public KeyTransRecipientInfo(
      RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKey) {
    this(new Asn1Integer(Args.notNull(rid, "rid").getIssuerAndSerialNumber() != null ? 0 : 2),
        rid, keyEncryptionAlgorithm, Asn1Util.toOctetString(encryptedKey));
  }

  public KeyTransRecipientInfo(
      Asn1Integer version, RecipientIdentifier rid, AlgorithmIdentifier keyEncryptionAlgorithm,
      Asn1OctetString encryptedKey) {
    this.version = Args.notNull(version, "version");
    this.rid = Args.notNull(rid, "rid");
    this.keyEncryptionAlgorithm = Args.notNull(keyEncryptionAlgorithm, "keyEncryptionAlgorithm");
    this.encryptedKey = Args.notNull(encryptedKey, "encryptedKey");
  }

  public static KeyTransRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 4);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    RecipientIdentifier rid = RecipientIdentifier.fromAsn1(seq.getObjectAt(1));
    AlgorithmIdentifier keyEncryptionAlgorithm = AlgorithmIdentifier.fromSequenceElement(seq, 2);
    Asn1OctetString encryptedKey = seq.getOctetStringAt(3);
    return new KeyTransRecipientInfo(version, rid, keyEncryptionAlgorithm, encryptedKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public RecipientIdentifier getRid() {
    return rid;
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
    return new Asn1Sequence(version, rid, keyEncryptionAlgorithm, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    rid.toStringWithLineSep(buf, indentLevel, "rid", true);
    keyEncryptionAlgorithm.toStringWithLineSep(buf, indentLevel, "keyEncryptionAlgorithm", true);
    encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey", true);

    return deleteLastNewLine(buf);
  }
}
