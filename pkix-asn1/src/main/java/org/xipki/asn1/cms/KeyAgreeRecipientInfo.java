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
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KeyAgreeRecipientInfo ::= SEQUENCE {
 *     version                     CMSVersion,  -- always set to 3
 *     originator              [0] EXPLICIT OriginatorIdentifierOrKey,
 *     ukm                     [1] EXPLICIT UserKeyingMaterial OPTIONAL,
 *     keyEncryptionAlgorithm      KeyEncryptionAlgorithmIdentifier,
 *     recipientEncryptedKeys      RecipientEncryptedKeys
 * }
 *
 * RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
 *
 * RecipientEncryptedKey ::= SEQUENCE {
 *     rid           KeyAgreeRecipientIdentifier,
 *     encryptedKey  EncryptedKey }
 *
 * EncryptedKey ::= OCTET STRING
 *
 * UserKeyingMaterial ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KeyAgreeRecipientInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final OriginatorIdentifierOrKey originator;
  private final Asn1OctetString ukm;
  private final AlgorithmIdentifier keyEncryptionAlgorithm;
  private final RecipientEncryptedKey.Seq0 recipientEncryptedKeys;

  public KeyAgreeRecipientInfo(
      OriginatorIdentifierOrKey originator, Asn1OctetString ukm,
      AlgorithmIdentifier keyEncryptionAlgorithm,
      RecipientEncryptedKey.Seq0 recipientEncryptedKeys) {
    this.version = Asn1Integer.THREE;
    this.originator = Args.notNull(originator, "originator");
    this.ukm = ukm;
    this.keyEncryptionAlgorithm = Args.notNull(keyEncryptionAlgorithm, "keyEncryptionAlgorithm");
    this.recipientEncryptedKeys = Args.notNull(recipientEncryptedKeys, "recipientEncryptedKeys");
  }

  public static KeyAgreeRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 4, 5);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(3)) {
      throw new CodecException("invalid version " + version);
    }
    OriginatorIdentifierOrKey originator = OriginatorIdentifierOrKey.fromAsn1(
        seq.getTaggedAt(1, 0).getExplicitBase());

    int index = 2;
    Asn1OctetString ukm = seq.isNotTaggedAt(index, 1) ? null
        : seq.getTaggedAt(index++).getExplicitOctetStringBase();

    AlgorithmIdentifier keyEncryptionAlgorithm =
        AlgorithmIdentifier.fromSequenceElement(seq, index++);
    RecipientEncryptedKey.Seq0 recipientEncryptedKeys =
        RecipientEncryptedKey.Seq0.fromAsn1(seq.getSequenceAt(index++));

    Asn1Util.checkSequenceEnd(index, size);
    return new KeyAgreeRecipientInfo(originator, ukm, keyEncryptionAlgorithm,
        recipientEncryptedKeys);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public OriginatorIdentifierOrKey getOriginator() {
    return originator;
  }

  public Asn1OctetString getUkm() {
    return ukm;
  }

  public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
    return keyEncryptionAlgorithm;
  }

  public RecipientEncryptedKey.Seq0 getRecipientEncryptedKeys() {
    return recipientEncryptedKeys;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] ukm() {
    return Asn1Util.fromAsn1(ukm);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version,
        Asn1TaggedObject.newExplicit(0, originator),
        (ukm == null ? null : Asn1TaggedObject.newExplicit(1, ukm)),
        keyEncryptionAlgorithm, recipientEncryptedKeys);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    originator.toStringWithLineSep(buf, indentLevel, "originator", true);

    if (ukm != null) {
      ukm.toStringWithLineSep(buf, indentLevel, "ukm", true);
    }

    keyEncryptionAlgorithm.toStringWithLineSep(buf, indentLevel, "keyEncryptionAlgorithm", true);
    recipientEncryptedKeys.toStringWithLineSep(buf, indentLevel, "recipientEncryptedKeys", true);

    return deleteLastNewLine(buf);
  }

}
