// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.cms.EnvelopedData;
import org.xipki.asn1.crmf.EncryptedKey;
import org.xipki.asn1.crmf.EncryptedValue;
import org.xipki.asn1.crmf.PKIPublicationInfo;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 9810:
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * CertifiedKeyPair ::= SEQUENCE {
 *     certOrEncCert       CertOrEncCert,
 *     privateKey      [0] EncryptedKey      OPTIONAL,
 *                         -- see [CRMF] for comment on encoding
 *     publicationInfo [1] PKIPublicationInfo  OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertifiedKeyPair extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<CertifiedKeyPair> {

    public Seq1(CertifiedKeyPair... entries) {
      super(entries);
    }

    public Seq1(List<CertifiedKeyPair> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected CertifiedKeyPair newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return CertifiedKeyPair.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final CertOrEncCert certOrEncCert;
  private final EncryptedKey privateKey;
  private final PKIPublicationInfo publicationInfo;

  public static CertifiedKeyPair fromAsn1(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertifiedKeyPair fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    CertOrEncCert certOrEncCert = CertOrEncCert.fromAsn1(seq.getTaggedAt(0));

    int index = 1;
    EncryptedKey privateKey = seq.isNotTaggedAt(index, 0) ? null
        : EncryptedKey.fromAsn1(seq.getTaggedAt(index++).getExplicitBase());

    PKIPublicationInfo publicationInfo = seq.isNotTaggedAt(index, 1) ? null
        : PKIPublicationInfo.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    return new CertifiedKeyPair(certOrEncCert, privateKey, publicationInfo);
  }

  public CertifiedKeyPair(CertOrEncCert certOrEncCert) {
    this(certOrEncCert, (EncryptedKey) null, null);
  }

  public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedKey privateKey,
                          PKIPublicationInfo publicationInfo) {
    this.certOrEncCert = Args.notNull(certOrEncCert, "certOrEncCert");
    this.privateKey = privateKey;
    this.publicationInfo = publicationInfo;
  }

  public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedValue privateKey,
                          PKIPublicationInfo publicationInfo) {
    this(certOrEncCert,
        (privateKey != null) ? EncryptedKey.ofEncryptedKey(privateKey) : null,
        publicationInfo);
  }

  public CertifiedKeyPair(CertOrEncCert certOrEncCert, EnvelopedData privateKey,
                          PKIPublicationInfo publicationInfo) {
    this(certOrEncCert,
        (privateKey != null) ? EncryptedKey.ofEnvelopedData(privateKey) : null,
        publicationInfo);
  }

  public CertOrEncCert getCertOrEncCert() {
    return certOrEncCert;
  }

  public EncryptedKey getPrivateKey() {
    return privateKey;
  }

  public PKIPublicationInfo getPublicationInfo() {
    return publicationInfo;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certOrEncCert,
        privateKey      == null ? null : Asn1TaggedObject.newExplicit(0, privateKey),
        publicationInfo == null ? null : Asn1TaggedObject.newExplicit(1, publicationInfo));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certOrEncCert.toStringWithLineSep(buf, indentLevel, "certOrEncCert", true);
    if (privateKey != null) {
      privateKey.toStringWithLineSep(buf, indentLevel, "privateKey", true);
    }

    if (publicationInfo != null) {
      publicationInfo.toStringWithLineSep(buf, indentLevel, "publicationInfo", true);
    }

    return deleteLastNewLine(buf);
  }
}
