// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * KeyAgreeRecipientIdentifier ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     rKeyId [0] IMPLICIT RecipientKeyIdentifier }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KeyAgreeRecipientIdentifier extends Asn1Encodable {

  private final IssuerAndSerialNumber issuerSerial;
  private final RecipientKeyIdentifier rKeyID;

  public static KeyAgreeRecipientIdentifier fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1Sequence) {
      return KeyAgreeRecipientIdentifier.ofIssuerAndSerialNumber(
                IssuerAndSerialNumber.fromAsn1(asn1.asSequence()));
    } else if (asn1 instanceof Asn1TaggedObject && asn1.getTagNo() == 0) {
      return KeyAgreeRecipientIdentifier.ofRKeyID(RecipientKeyIdentifier.fromAsn1(
                asn1.asTagged().getImplicitSequenceBase()));
    } else {
      throw new CodecException("invalid asn1 type");
    }
  }

  private KeyAgreeRecipientIdentifier(
      IssuerAndSerialNumber issuerSerial, RecipientKeyIdentifier rKeyID) {
    this.issuerSerial = issuerSerial;
    this.rKeyID = rKeyID;
  }

  public static KeyAgreeRecipientIdentifier ofIssuerAndSerialNumber(
      IssuerAndSerialNumber issuerSerial) {
    return new KeyAgreeRecipientIdentifier(Args.notNull(issuerSerial, "issuerSerial"), null);
  }

  public static KeyAgreeRecipientIdentifier ofRKeyID(RecipientKeyIdentifier rKeyID) {
    return new KeyAgreeRecipientIdentifier(null, Args.notNull(rKeyID, "rKeyID"));
  }

  public IssuerAndSerialNumber getIssuerAndSerialNumber() {
    return issuerSerial;
  }

  public RecipientKeyIdentifier getRKeyID() {
    return rKeyID;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return issuerSerial != null ? issuerSerial.toAsn1Primitive()
        : Asn1TaggedObject.newImplicit(0, rKeyID);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (issuerSerial != null) {
      return issuerSerial.toStringWithLineSep(buf, indentLevel, "issuerSerial");
    }

    return rKeyID.toStringWithLineSep(buf, indentLevel, "rKeyID");
  }

}
