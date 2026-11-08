// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KEKRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 4
 *     kekid KEKIdentifier,
 *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey EncryptedKey
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KEKRecipientInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final KEKIdentifier kekid;
  private final AlgorithmIdentifier keyEncryptionAlgorithm;
  private final Asn1OctetString encryptedKey;

  public KEKRecipientInfo(
      KEKIdentifier kekid, AlgorithmIdentifier keyEncryptionAlgorithm,
      Asn1OctetString encryptedKey) {
      this.version = Asn1Integer.FOUR;
      this.kekid = Args.notNull(kekid, "kekid");
      this.keyEncryptionAlgorithm = Args.notNull(keyEncryptionAlgorithm, "keyEncryptionAlgorithm");
      this.encryptedKey = Args.notNull(encryptedKey, "encryptedKey");
  }

  public static KEKRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 4);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(4)) {
      throw new CodecException("invalid version " + version);
    }
    KEKIdentifier kekid = KEKIdentifier.fromAsn1(seq.getSequenceAt(1));
    AlgorithmIdentifier keyEncryptionAlgorithm = AlgorithmIdentifier.fromSequenceElement(seq,2);
    Asn1OctetString encryptedKey = seq.getOctetStringAt(3);
    return new KEKRecipientInfo(kekid, keyEncryptionAlgorithm, encryptedKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public KEKIdentifier getKekid() {
    return kekid;
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
    return new Asn1Sequence(version, kekid, keyEncryptionAlgorithm, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    kekid.toStringWithLineSep(buf, indentLevel, "kekid", true);
    keyEncryptionAlgorithm.toStringWithLineSep(buf, indentLevel, "keyEncryptionAlgorithm", true);
    encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey", true);

    return deleteLastNewLine(buf);
  }
}
