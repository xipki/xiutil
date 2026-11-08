// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 4211:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * POPOPrivKey ::= CHOICE {
 *     thisMessage       [0] BIT STRING,         -- Deprecated
 *         -- possession is proven in this message (which contains the private
 *         -- key itself (encrypted for the CA))
 *     subsequentMessage [1] SubsequentMessage,
 *         -- possession will be proven in a subsequent message
 *     dhMAC             [2] BIT STRING,         -- Deprecated
 *     agreeMAC          [3] PKMACValue,
 *     encryptedKey      [4] EnvelopedData
 * }
 *
 * SubsequentMessage ::= INTEGER {
 *     encrCert (0),
 *     challengeResp (1) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class POPOPrivKey extends Asn1Encodable {

  private final Asn1BitString thisMessage;
  private final Asn1Integer subsequentMessage;
  private final Asn1BitString dhMAC;
  private final PKMACValue agreeMAC;
  private final EnvelopedData encryptedKey;

  private POPOPrivKey(
      Asn1BitString thisMessage, Asn1Integer subsequentMessage,
      Asn1BitString dhMAC, PKMACValue agreeMAC, EnvelopedData encryptedKey) {
    this.thisMessage = thisMessage;
    this.subsequentMessage = subsequentMessage;
    this.dhMAC = dhMAC;
    this.agreeMAC = agreeMAC;
    this.encryptedKey = encryptedKey;
  }

  public static POPOPrivKey ofThisMessage(Asn1BitString thisMessage) {
    return new POPOPrivKey(Args.notNull(thisMessage, "thisMessage"),
        null, null, null, null);
  }

  public static POPOPrivKey ofSubsequentMessage(Asn1Integer subsequentMessage) {
    Args.notNull(subsequentMessage, "subsequentMessage");
    if (!(subsequentMessage.hasValue(0) || subsequentMessage.hasValue(1))) {
      throw new IllegalArgumentException("invalid subsequentMessage" + subsequentMessage);
    }
    return new POPOPrivKey(null, subsequentMessage, null, null, null);
  }

  public static POPOPrivKey ofDhMAC(Asn1BitString dhMAC) {
    return new POPOPrivKey(null, null, Args.notNull(dhMAC, "dhMAC"),
        null, null);
  }

  public static POPOPrivKey ofAgreeMAC(PKMACValue agreeMAC) {
    return new POPOPrivKey(null, null, null,
        Args.notNull(agreeMAC, "agreeMAC"), null);
  }

  public static POPOPrivKey ofEncryptedKey(EnvelopedData encryptedKey) {
    return new POPOPrivKey(null, null, null, null,
        Args.notNull(encryptedKey, "encryptedKey"));
  }

  public static POPOPrivKey fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    int tagNo = asn1.getTagNo();

    if (tagNo == 0) {
      return ofThisMessage(asn1.getImplicitBitStringBase());
    } else if (tagNo == 1) {
      return ofSubsequentMessage(Asn1Integer.checkNonNegative(asn1.getImplicitIntegerBase()));
    } else if (tagNo == 2) {
      return ofDhMAC(asn1.getImplicitBitStringBase());
    } else if (tagNo == 3) {
      return ofAgreeMAC(PKMACValue.fromAsn1(asn1.getImplicitSequenceBase()));
    } else if (tagNo == 4) {
      return ofEncryptedKey(EnvelopedData.fromAsn1(asn1.getImplicitSequenceBase()));
    } else {
      throw new IllegalArgumentException("unknown tag in POPOPrivKey " + tagNo);
    }
  }

  public Asn1BitString getThisMessage() {
    return thisMessage;
  }

  public Asn1Integer getSubsequentMessage() {
    return subsequentMessage;
  }

  public Asn1BitString getDhMAC() {
    return dhMAC;
  }

  public PKMACValue getAgreeMAC() {
    return agreeMAC;
  }

  public EnvelopedData getEncryptedKey() {
    return encryptedKey;
  }

  public byte[] thisMessage() {
    return Asn1Util.fromAsn1(thisMessage);
  }

  public Integer subsequentMessage() {
    return Asn1Util.fromAsn1Int(subsequentMessage);
  }

  public byte[] dhMAC() {
    return Asn1Util.fromAsn1(dhMAC);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return thisMessage != null ? Asn1TaggedObject.newImplicit(0, thisMessage)
        : subsequentMessage != null ? Asn1TaggedObject.newImplicit(1, subsequentMessage)
        : dhMAC != null ? Asn1TaggedObject.newImplicit(2, dhMAC)
        : agreeMAC != null ? Asn1TaggedObject.newImplicit(3, agreeMAC)
        : Asn1TaggedObject.newImplicit(4, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (thisMessage != null) {
      return thisMessage.toStringWithLineSep(buf, indentLevel, "thisMessage");
    }

    if (subsequentMessage != null) {
      return subsequentMessage.toStringNoLineSep(buf, indentLevel, "subsequentMessage");
    }

    if (dhMAC != null) {
      return dhMAC.toStringWithLineSep(buf, indentLevel, "dhMAC");
    }

    if (agreeMAC != null) {
      return agreeMAC.toStringWithLineSep(buf, indentLevel, "agreeMAC");
    }

    return encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey");
  }

}
