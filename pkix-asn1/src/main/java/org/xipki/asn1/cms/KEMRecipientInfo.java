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
 * <p>
 * Defined in <a href="https://datatracker.ietf.org/doc/rfc9629/">RFC 9629</a>.
 * </p>
 * <pre>
 * KEMRecipientInfo ::= SEQUENCE {
 *     version       CMSVersion,  -- always set to 0
 *     rid           RecipientIdentifier,
 *     kem           KEMAlgorithmIdentifier,
 *     kemct         OCTET STRING,
 *     kdf           KeyDerivationAlgorithmIdentifier,
 *     kekLength     INTEGER (1..65535),
 *     ukm           [0] EXPLICIT UserKeyingMaterial OPTIONAL,
 *     wrap          KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey  EncryptedKey
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KEMRecipientInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final RecipientIdentifier rid;
  private final AlgorithmIdentifier kem;
  private final Asn1OctetString kemct;
  private final AlgorithmIdentifier kdf;
  private final Asn1Integer kekLength;
  private final Asn1OctetString ukm;
  private final AlgorithmIdentifier wrap;
  private final Asn1OctetString encryptedKey;

  public KEMRecipientInfo(
      RecipientIdentifier rid, AlgorithmIdentifier kem, Asn1OctetString kemct,
      AlgorithmIdentifier kdf, Asn1Integer kekLength, Asn1OctetString ukm,
      AlgorithmIdentifier wrap, Asn1OctetString encryptedKey) {
    this.version = Asn1Integer.ZERO;
    this.rid = Args.notNull(rid, "rid");
    this.kem = Args.notNull(kem, "kem");
    this.kemct = Args.notNull(kemct, "kemct");
    this.kdf = Args.notNull(kdf, "kdf");
    this.kekLength = Args.notNull(kekLength, "kekLength");
    Args.range(kekLength.intValueExact(), "kekLength", 1, 65535);
    this.ukm = ukm;
    this.wrap = Args.notNull(wrap, "wrap");
    this.encryptedKey = Args.notNull(encryptedKey, "encryptedKey");
  }

  public static KEMRecipientInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 8, 9);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    if (!version.hasValue(0)) {
      throw new CodecException("invalid version " + version);
    }

    RecipientIdentifier rid = RecipientIdentifier.fromAsn1(seq.getObjectAt(1));
    AlgorithmIdentifier kem = AlgorithmIdentifier.fromSequenceElement(seq, 2);
    Asn1OctetString kemct = seq.getOctetStringAt(3);
    AlgorithmIdentifier kdf = AlgorithmIdentifier.fromSequenceElement(seq, 4);
    Asn1Integer kekLength = seq.getNonNegativeIntegerAt(5);
    int iLen = kekLength.intValueExact();
    if (iLen < 1 || iLen > 65535) {
      throw new CodecException("kekLength non in [1, 65535]");
    }

    int index = 6;
    Asn1OctetString ukm = seq.isNotTaggedAt(index, 0) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    AlgorithmIdentifier wrap = AlgorithmIdentifier.fromSequenceElement(seq, index++);
    Asn1OctetString encryptedKey = seq.getOctetStringAt(index++);

    Asn1Util.checkSequenceEnd(index, size);
    return new KEMRecipientInfo(rid, kem, kemct, kdf, kekLength, ukm, wrap, encryptedKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public RecipientIdentifier getRid() {
    return rid;
  }

  public AlgorithmIdentifier getKem() {
    return kem;
  }

  public Asn1OctetString getKemct() {
    return kemct;
  }

  public AlgorithmIdentifier getKdf() {
    return kdf;
  }

  public Asn1Integer getKekLength() {
    return kekLength;
  }

  public Asn1OctetString getUkm() {
    return ukm;
  }

  public AlgorithmIdentifier getWrap() {
    return wrap;
  }

  public Asn1OctetString getEncryptedKey() {
    return encryptedKey;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] kemct() {
    return kemct.getOctets();
  }

  public int kekLength() {
    return kekLength.intValueExact();
  }

  public byte[] ukm() {
    return Asn1Util.fromAsn1(ukm);
  }

  public byte[] encryptedKey() {
    return encryptedKey.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, rid, kem, kemct, kdf, kekLength,
        (ukm == null ? null : Asn1TaggedObject.newExplicit(0, ukm)),
        wrap, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (version != null) {
      version.toStringNoLineSep(buf, indentLevel, "version", true);
    }

    rid.toStringWithLineSep(buf, indentLevel, "rid", true);
    kem.toStringWithLineSep(buf, indentLevel, "kem", true);
    kemct.toStringWithLineSep(buf, indentLevel, "kemct", true);
    kdf.toStringWithLineSep(buf, indentLevel, "kdf", true);
    kekLength.toStringNoLineSep(buf, indentLevel, "kekLength", true);

    if (ukm != null) {
      ukm.toStringWithLineSep(buf, indentLevel, "ukm", true);
    }

    wrap.toStringWithLineSep(buf, indentLevel, "wrap", true);
    encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey", true);

    return deleteLastNewLine(buf);
  }

}
