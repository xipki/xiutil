// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms.ecc;

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
 * RFC 5753:
 * <pre>
 *     ECC-CMS-SharedInfo ::= SEQUENCE {
 *        keyInfo AlgorithmIdentifier,
 *        entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
 *        suppPubInfo [2] EXPLICIT OCTET STRING   }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EccCmsSharedInfo extends Asn1Encodable {

  private final AlgorithmIdentifier keyInfo;
  private final Asn1OctetString entityUInfo;
  private final Asn1OctetString suppPubInfo;

  public EccCmsSharedInfo(AlgorithmIdentifier keyInfo, Asn1OctetString suppPubInfo) {
    this(keyInfo, null, suppPubInfo);
  }

  public EccCmsSharedInfo(AlgorithmIdentifier keyInfo, byte[] entityUInfo, byte[] suppPubInfo) {
    this(keyInfo, Asn1Util.toOctetString(entityUInfo), Asn1Util.toOctetString(suppPubInfo));
  }

  public EccCmsSharedInfo(AlgorithmIdentifier keyInfo, Asn1OctetString entityUInfo,
                          Asn1OctetString suppPubInfo) {
    this.keyInfo = Args.notNull(keyInfo, "keyInfo");
    this.entityUInfo = entityUInfo;
    this.suppPubInfo = Args.notNull(suppPubInfo, "suppPubInfo");
  }

  public static EccCmsSharedInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    AlgorithmIdentifier keyInfo = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));

    int index = 1;
    Asn1OctetString entityUInfo = seq.isNotTaggedAt(index, 0) ? null
        : seq.getOctetStringTaggedAt(index++, true);
    Asn1Util.checkSequenceEnd(index, size - 1);

    Asn1OctetString suppPubInfo = seq.getTaggedAt(index, 2).getExplicitOctetStringBase();
    return new EccCmsSharedInfo(keyInfo, entityUInfo, suppPubInfo);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(keyInfo,
        (entityUInfo == null) ? null : Asn1TaggedObject.newExplicit(0, entityUInfo),
        Asn1TaggedObject.newExplicit(2, suppPubInfo));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    keyInfo.toStringWithLineSep(buf, indentLevel, "keyInfo", true);

    if (entityUInfo != null) {
      entityUInfo.toStringWithLineSep(buf, indentLevel, "entityUInfo", true);
    }

    suppPubInfo.toStringWithLineSep(buf, indentLevel, "suppPubInfo", true);

    return deleteLastNewLine(buf);
  }

  public AlgorithmIdentifier getKeyInfo() {
    return keyInfo;
  }

  public Asn1OctetString getEntityUInfo() {
    return entityUInfo;
  }

  public Asn1OctetString getSuppPubInfo() {
    return suppPubInfo;
  }

  public byte[] entityUInfo() {
    return Asn1Util.fromAsn1(entityUInfo);
  }

  public byte[] suppPubInfo() {
    return suppPubInfo.getOctets();
  }
}
