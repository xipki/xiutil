// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * InfoTypeAndValue ::= SEQUENCE {
 *     infoType  OBJECT IDENTIFIER,
 *     infoValue ANY DEFINED BY infoType  OPTIONAL
 * }
 * </pre>
 *
 * Example InfoTypeAndValue contents include, but are not limited
 * to, the following (un-comment in this ASN.1 module and use as
 * appropriate for a given environment):
 * <pre>
 *   id-it-caProtEncCert    OBJECT IDENTIFIER ::= {id-it 1}
 *      CAProtEncCertValue      ::= CMPCertificate
 *   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
 *     SignKeyPairTypesValue   ::= SEQUENCE OF AlgorithmIdentifier
 *   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}
 *     EncKeyPairTypesValue    ::= SEQUENCE OF AlgorithmIdentifier
 *   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
 *      PreferredSymmAlgValue   ::= AlgorithmIdentifier
 *   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
 *      CAKeyUpdateInfoValue    ::= CAKeyUpdAnnContent
 *   id-it-currentCRL       OBJECT IDENTIFIER ::= {id-it 6}
 *      CurrentCRLValue         ::= CertificateList
 *   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
 *      UnsupportedOIDsValue    ::= SEQUENCE OF OBJECT IDENTIFIER
 *   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
 *      KeyPairParamReqValue    ::= OBJECT IDENTIFIER
 *   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
 *      KeyPairParamRepValue    ::= AlgorithmIdentifer
 *   id-it-revPassphrase    OBJECT IDENTIFIER ::= {id-it 12}
 *      RevPassphraseValue      ::= EncryptedValue
 *   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
 *      ImplicitConfirmValue    ::= NULL
 *   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
 *      ConfirmWaitTimeValue    ::= GeneralizedTime
 *   id-it-origPKIMessage   OBJECT IDENTIFIER ::= {id-it 15}
 *      OrigPKIMessageValue     ::= PKIMessages
 *   id-it-suppLangTags     OBJECT IDENTIFIER ::= {id-it 16}
 *      SuppLangTagsValue       ::= SEQUENCE OF UTF8String
 *
 * where
 *
 *   id-pkix OBJECT IDENTIFIER ::= {
 *      iso(1) identified-organization(3)
 *      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
 * and
 *      id-it   OBJECT IDENTIFIER ::= {id-pkix 4}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class InfoTypeAndValue extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<InfoTypeAndValue> {

    public Seq1(InfoTypeAndValue... entries) {
      super(entries);
    }

    public Seq1(List<InfoTypeAndValue> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected InfoTypeAndValue newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return InfoTypeAndValue.fromAsn1(coll.getSequenceAt(index));
    }
  }

  public static class Seq0 extends AbstractSeq0<InfoTypeAndValue> {

    public Seq0(InfoTypeAndValue... entries) {
      super(entries);
    }

    public Seq0(List<InfoTypeAndValue> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected InfoTypeAndValue newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return InfoTypeAndValue.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid infoType;
  private final Asn1Primitive infoValue;

  public static InfoTypeAndValue fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid infoType = seq.getOidAt(0);
    Asn1Primitive infoValue = (size == 1) ? null : seq.getObjectAt(1);
    return new InfoTypeAndValue(infoType, infoValue);
  }

  public static InfoTypeAndValue build(Asn1Oid infoType, Asn1Encodable infoValue) {
    return new InfoTypeAndValue(infoType, (infoValue == null) ? null : infoValue.toAsn1Primitive());
  }

  public InfoTypeAndValue(Asn1Oid infoType, Asn1Primitive infoValue) {
    this.infoType = Args.notNull(infoType, "infoType");
    this.infoValue = infoValue;
  }

  public Asn1Oid getInfoType() {
    return infoType;
  }

  public Asn1Primitive getInfoValue() {
    return infoValue;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(infoType, infoValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    infoType.toStringNoLineSep(buf, indentLevel, "infoType", true);

    if (infoValue != null) {
      infoValue.toStringWithLineSep(buf, indentLevel, "infoValue", true);
    }

    return deleteLastNewLine(buf);
  }
}
