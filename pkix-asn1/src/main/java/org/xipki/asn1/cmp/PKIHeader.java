// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * PKIHeader ::= SEQUENCE {
 *     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
 *     sender              GeneralName,
 *          -- identifies the sender
 *     recipient           GeneralName,
 *          -- identifies the intended recipient
 *     messageTime     [0] GeneralizedTime         OPTIONAL,
 *          -- time of production of this message (used when sender
 *          -- believes that the transport will be "suitable"; i.e.,
 *          -- that the time will still be meaningful upon receipt)
 *     protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
 *          -- algorithm used for calculation of protection bits
 *     senderKID       [2] KeyIdentifier           OPTIONAL,
 *     recipKID        [3] KeyIdentifier           OPTIONAL,
 *          -- to identify specific keys used for protection
 *     transactionID   [4] OCTET STRING            OPTIONAL,
 *          -- identifies the transaction; i.e., this will be the same in
 *          -- corresponding request, response, certConf, and PKIConf
 *          -- messages
 *     senderNonce     [5] OCTET STRING            OPTIONAL,
 *     recipNonce      [6] OCTET STRING            OPTIONAL,
 *          -- nonces used to provide replay protection, senderNonce
 *          -- is inserted by the creator of this message; recipNonce
 *          -- is a nonce previously inserted in a related message by
 *          -- the intended recipient of this message
 *     freeText        [7] PKIFreeText             OPTIONAL,
 *          -- this may be used to indicate context-specific instructions
 *          -- (this field is intended for human consumption)
 *     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
 *                                 InfoTypeAndValue     OPTIONAL
 *          -- this may be used to convey context-specific information
 *          -- (this field not primarily intended for human consumption)
 *  }
 *
 * @author Lijun Liao (xipki)
 */
public class PKIHeader extends Asn1Encodable {

  public static final GeneralName NULL_NAME = GeneralName.ofDirectoryName(new X500Name());

  public static final int CMP_1999 = 1;
  public static final int CMP_2000 = 2;
  public static final int CMP_2021 = 3;

  private Asn1Integer pvno;
  private final GeneralName sender;
  private final GeneralName recipient;
  private Asn1GeneralizedTime messageTime;
  private AlgorithmIdentifier protectionAlg;
  private Asn1OctetString senderKID;       // KeyIdentifier
  private Asn1OctetString recipKID;        // KeyIdentifier
  private Asn1OctetString transactionID;
  private Asn1OctetString senderNonce;
  private Asn1OctetString recipNonce;
  private PKIFreeText freeText;
  private InfoTypeAndValue.Seq1 generalInfo;

  public static PKIHeader fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 12);
    Asn1Integer pvno = seq.getNonNegativeIntegerAt(0);
    GeneralName sender = GeneralName.fromAsn1(seq.getTaggedAt(1));
    GeneralName recipient = GeneralName.fromAsn1(seq.getTaggedAt(2));

    PKIHeader header = new PKIHeader(pvno, sender, recipient);

    int index = 3;
    // *     messageTime     [0] GeneralizedTime         OPTIONAL,
    header.messageTime = seq.isNotTaggedAt(index, 0) ? null
        : seq.getGeneralizedTimeTaggedAt(index++, true);

    // *     protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
    header.protectionAlg = seq.isNotTaggedAt(index, 1) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    // *     senderKID       [2] KeyIdentifier           OPTIONAL,
    header.senderKID = seq.isNotTaggedAt(index, 2) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    // *     recipKID        [3] KeyIdentifier           OPTIONAL,
    header.recipKID = seq.isNotTaggedAt(index, 3) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    // *     transactionID   [4] OCTET STRING            OPTIONAL,
    header.transactionID = seq.isNotTaggedAt(index, 4) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    // *     senderNonce     [5] OCTET STRING            OPTIONAL,
    header.senderNonce = seq.isNotTaggedAt(index, 5) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    // *     recipNonce      [6] OCTET STRING            OPTIONAL,
    header.recipNonce = seq.isNotTaggedAt(index, 6) ? null
        : seq.getOctetStringTaggedAt(index++, true);

    // *     freeText        [7] PKIFreeText             OPTIONAL,
    header.freeText = seq.isNotTaggedAt(index, 7) ? null
        : PKIFreeText.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    // *     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
    // *                                 InfoTypeAndValue     OPTIONAL
    header.generalInfo = seq.isNotTaggedAt(index, 8) ? null
        : InfoTypeAndValue.Seq1.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    return header;
  }

  public PKIHeader(int pvno, GeneralName sender, GeneralName recipient) {
    this(new Asn1Integer(pvno), sender, recipient);
  }

  private PKIHeader(Asn1Integer pvno, GeneralName sender, GeneralName recipient) {
    this.pvno = Args.notNull(pvno, "pvno");
    this.sender = Args.notNull(sender, "sender");
    this.recipient = Args.notNull(recipient, "recipient");
  }

  public void setPvno(int version) {
    pvno = new Asn1Integer(version);
  }

  public Asn1Integer getPvno() {
    return pvno;
  }

  public int pvno() {
    return pvno.intValueExact();
  }

  public GeneralName getSender() {
    return sender;
  }

  public GeneralName getRecipient() {
    return recipient;
  }

  public Asn1GeneralizedTime getMessageTime() {
    return messageTime;
  }

  public Instant messageTime() {
    return Asn1Util.fromAsn1(messageTime);
  }

  public void setMessageTime(Asn1GeneralizedTime messageTime) {
    this.messageTime = messageTime;
  }

  public void setMessageTime(Instant messageTime) {
    setMessageTime(Asn1Util.toGeneralizedDate(messageTime));
  }

  public AlgorithmIdentifier getProtectionAlg() {
    return protectionAlg;
  }

  public void setProtectionAlg(AlgorithmIdentifier protectionAlg) {
    this.protectionAlg = protectionAlg;
  }

  public Asn1OctetString getSenderKID() {
    return senderKID;
  }

  public byte[] senderKID() {
    return Asn1Util.fromAsn1(senderKID);
  }

  public void setSenderKID(Asn1OctetString senderKID) {
    this.senderKID = senderKID;
  }

  public void setSenderKID(byte[] senderKID) {
    setSenderKID(Asn1Util.toOctetString(senderKID));
  }

  public Asn1OctetString getRecipKID() {
    return recipKID;
  }

  public byte[] recipKID() {
    return Asn1Util.fromAsn1(recipKID);
  }

  public void setRecipKID(Asn1OctetString recipKID) {
    this.recipKID = recipKID;
  }

  public void setRecipKID(byte[] recipKID) {
    setRecipKID(Asn1Util.toOctetString(recipKID));
  }

  public Asn1OctetString getTransactionID() {
    return transactionID;
  }

  public byte[] transactionID() {
    return Asn1Util.fromAsn1(transactionID);
  }

  public void setTransactionID(Asn1OctetString transactionID) {
    this.transactionID = transactionID;
  }

  public void setTransactionID(byte[] transactionID) {
    setTransactionID(Asn1Util.toOctetString(transactionID));
  }

  public Asn1OctetString getSenderNonce() {
    return senderNonce;
  }

  public byte[] senderNonce() {
    return Asn1Util.fromAsn1(senderNonce);
  }

  public void setSenderNonce(Asn1OctetString senderNonce) {
    this.senderNonce = senderNonce;
  }

  public void setSenderNonce(byte[] senderNonce) {
    setSenderNonce(Asn1Util.toOctetString(senderNonce));
  }

  public Asn1OctetString getRecipNonce() {
    return recipNonce;
  }

  public byte[] recipNonce() {
    return Asn1Util.fromAsn1(recipNonce);
  }

  public void setRecipNonce(Asn1OctetString recipNonce) {
    this.recipNonce = recipNonce;
  }

  public void setRecipNonce(byte[] recipNonce) {
    setRecipNonce(Asn1Util.toOctetString(recipNonce));
  }

  public PKIFreeText getFreeText() {
    return freeText;
  }

  public void setFreeText(PKIFreeText freeText) {
    this.freeText = freeText;
  }

  public InfoTypeAndValue.Seq1 getGeneralInfo() {
    return generalInfo;
  }

  public void setGeneralInfo(InfoTypeAndValue.Seq1 generalInfo) {
    this.generalInfo = generalInfo;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(pvno, sender, recipient,
        optional(0, messageTime), optional(1, protectionAlg),
        optional(2, senderKID), optional(3, recipKID),
        optional(4, transactionID), optional(5, senderNonce),
        optional(6, recipNonce), optional(7, freeText),
        optional(8, generalInfo));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    pvno.toStringNoLineSep(buf, indentLevel, "pvno", true);
    sender.toStringWithLineSep(buf, indentLevel, "sender", true);
    recipient.toStringWithLineSep(buf, indentLevel, "recipient", true);

    if (messageTime != null) {
      messageTime.toStringNoLineSep(buf, indentLevel, "messageTime", true);
    }

    if (protectionAlg != null) {
      protectionAlg.toStringWithLineSep(buf, indentLevel, "protectionAlg", true);
    }

    if (senderKID != null) {
      senderKID.toStringWithLineSep(buf, indentLevel, "senderKID", true);
    }

    if (recipKID != null) {
      recipKID.toStringWithLineSep(buf, indentLevel, "recipKID", true);
    }

    if (transactionID != null) {
      transactionID.toStringWithLineSep(buf, indentLevel, "transactionID", true);
    }

    if (senderNonce != null) {
      senderNonce.toStringWithLineSep(buf, indentLevel, "senderNonce", true);
    }

    if (recipNonce != null) {
      recipNonce.toStringWithLineSep(buf, indentLevel, "recipNonce", true);
    }

    if (freeText != null) {
      freeText.toStringWithLineSep(buf, indentLevel, "freeText", true);
    }

    if (generalInfo != null) {
      generalInfo.toStringWithLineSep(buf, indentLevel, "generalInfo", true);
    }

    return deleteLastNewLine(buf);
  }

  private static Asn1TaggedObject optional(int tagNo, Asn1Encodable obj) {
     return obj == null ? null : Asn1TaggedObject.newExplicit(tagNo, obj);
  }

}
