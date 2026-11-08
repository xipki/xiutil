// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
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

import java.math.BigInteger;
import java.util.List;

/**
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * RFC 4210:
 *
 * CertStatus ::= SEQUENCE {
 *    certHash    OCTET STRING,
 *    -- the hash of the certificate, using the same hash algorithm
 *    -- as is used to create and verify the certificate signature
 *    certReqId   INTEGER,
 *    -- to match this confirmation with the corresponding req/rep
 *    statusInfo  PKIStatusInfo OPTIONAL
 * }
 *
 * RFC 9810:
 * CertStatus ::= SEQUENCE {
 *   certHash    OCTET STRING,
 *   certReqId   INTEGER,
 *   statusInfo  PKIStatusInfo OPTIONAL,
 *   hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CmpCertStatus extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<CmpCertStatus> {

    public Seq0(CmpCertStatus... entries) {
      super(entries);
    }

    public Seq0(List<CmpCertStatus> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromEncoded(byte[] encoded) throws CodecException {
      return fromAsn1(Asn1Sequence.fromEncoded(encoded));
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected CmpCertStatus newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return CmpCertStatus.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1OctetString certHash;
  private final Asn1Integer certReqId;
  private final PKIStatusInfo statusInfo;
  private final AlgorithmIdentifier hashAlg;

  public static CmpCertStatus fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    Asn1OctetString certHash = seq.getOctetStringAt(0);
    Asn1Integer certReqId = seq.getIntegerAt(1);

    // *   statusInfo  PKIStatusInfo OPTIONAL,
    // *   hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
    int index = 2;
    PKIStatusInfo statusInfo = seq.notHasSequence(index) ? null
        : PKIStatusInfo.fromAsn1(seq.getSequenceAt(index++));

    AlgorithmIdentifier hashAlg = seq.isNotTaggedAt(index, 0) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);

    return new CmpCertStatus(certHash, certReqId, statusInfo, hashAlg);
  }

  public CmpCertStatus(byte[] certHash, BigInteger certReqId) {
    this(certHash, certReqId, null, null);
  }

  public CmpCertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo) {
    this(certHash, certReqId, statusInfo, null);
  }

  public CmpCertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo,
                       AlgorithmIdentifier hashAlg) {
    this.certHash = new Asn1OctetString(Args.notNull(certHash, "certHash"));
    this.certReqId = new Asn1Integer(Args.notNull(certReqId, "certReqId"));
    this.statusInfo = statusInfo;
    this.hashAlg = hashAlg;
  }

  public CmpCertStatus(Asn1OctetString certHash, Asn1Integer certReqId, PKIStatusInfo statusInfo,
                       AlgorithmIdentifier hashAlg) {
    this.certHash = Args.notNull(certHash, "certHash");
    this.certReqId = Args.notNull(certReqId, "certReqId");
    this.statusInfo = statusInfo;
    this.hashAlg = hashAlg;
  }

  public Asn1OctetString getCertHash() {
    return certHash;
  }

  public Asn1Integer getCertReqId() {
    return certReqId;
  }

  public PKIStatusInfo getStatusInfo() {
    return statusInfo;
  }

  public AlgorithmIdentifier getHashAlg() {
    return hashAlg;
  }

  public byte[] certHash() {
    return certHash.getOctets();
  }

  public BigInteger certReqId() {
    return certReqId.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    Asn1TaggedObject asn1HashAlg = (hashAlg == null) ? null
        : Asn1TaggedObject.newExplicit(0, hashAlg);
    return Asn1Sequence.buildIgnoreNull(certHash, certReqId, statusInfo, asn1HashAlg);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (hashAlg != null) {
      hashAlg.toStringWithLineSep(buf, indentLevel, "hashAlg", true);
    }

    certHash.toStringWithLineSep(buf, indentLevel, "certHash", true);
    certReqId.toStringNoLineSep(buf, indentLevel, "certReqId", true);

    if (statusInfo != null) {
      statusInfo.toStringWithLineSep(buf, indentLevel, "statusInfo", true);
    }

    return deleteLastNewLine(buf);
  }
}
