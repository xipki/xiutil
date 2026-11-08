// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 5652:
 * <pre>
 * EncryptedContentInfo ::= SEQUENCE {
 *     contentType                 ContentType,
 *     contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
 *     encryptedContent            [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 *
 * EncryptedContent ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptedContentInfo extends Asn1Encodable {

  private final Asn1Oid contentType;
  private final AlgorithmIdentifier contentEncryptionAlgorithm;
  private final Asn1OctetString encryptedContent;

  public EncryptedContentInfo(Asn1Oid contentType, AlgorithmIdentifier contentEncryptionAlgorithm,
                              Asn1OctetString encryptedContent) {
    this.contentType = Args.notNull(contentType, "contentType");
    this.contentEncryptionAlgorithm =
        Args.notNull(contentEncryptionAlgorithm, "contentEncryptionAlgorithm");
    this.encryptedContent = encryptedContent;
  }

  public EncryptedContentInfo(Asn1Oid contentType, AlgorithmIdentifier contentEncryptionAlgorithm,
                              byte[] encryptedContent) {
    this(contentType, contentEncryptionAlgorithm, Asn1Util.toOctetString(encryptedContent));
  }

  public static EncryptedContentInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Oid contentType = seq.getOidAt(0);
    AlgorithmIdentifier contentEncryptionAlgorithm =
        AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));

    int index = 2;
    Asn1OctetString encryptedContent = seq.isNotTaggedAt(index, 0) ? null
        : seq.getOctetStringTaggedAt(index++, false);
    Asn1Util.checkSequenceEnd(index, size);
    return new EncryptedContentInfo(contentType, contentEncryptionAlgorithm, encryptedContent);
  }

  public Asn1Oid getContentType() {
    return contentType;
  }

  public AlgorithmIdentifier getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public Asn1OctetString getEncryptedContent() {
    return encryptedContent;
  }

  public byte[] encryptedContent() {
    return Asn1Util.fromAsn1(encryptedContent);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(contentType, contentEncryptionAlgorithm,
        (encryptedContent == null ? null
            : Asn1TaggedObject.newImplicit(0, encryptedContent)));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    contentType.toStringNoLineSep(buf, indentLevel, "contentType", true);
    contentEncryptionAlgorithm.toStringWithLineSep(buf, indentLevel,
        "contentEncryptionAlgorithm", true);

    if (encryptedContent != null) {
      encryptedContent.toStringWithLineSep(buf, indentLevel, "encryptedContent", true);
    }

    return deleteLastNewLine(buf);
  }

}
