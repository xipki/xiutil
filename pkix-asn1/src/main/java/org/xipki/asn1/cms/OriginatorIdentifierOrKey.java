// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * OriginatorIdentifierOrKey ::= CHOICE {
 *     issuerAndSerialNumber     IssuerAndSerialNumber,
 *     subjectKeyIdentifier  [0] SubjectKeyIdentifier,
 *     originatorKey         [1] OriginatorPublicKey
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * OriginatorPublicKey ::= SEQUENCE { .. }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OriginatorIdentifierOrKey extends Asn1Encodable {

  private final IssuerAndSerialNumber issuerAndSerialNumber;
  private final Asn1OctetString subjectKeyIdentifier;
  private final OriginatorPublicKey originatorKey;

  private OriginatorIdentifierOrKey(
      IssuerAndSerialNumber issuerAndSerialNumber, Asn1OctetString subjectKeyIdentifier,
      OriginatorPublicKey originatorKey) {
    this.issuerAndSerialNumber = issuerAndSerialNumber;
    this.subjectKeyIdentifier = subjectKeyIdentifier;
    this.originatorKey = originatorKey;
  }

  public static OriginatorIdentifierOrKey ofIssuerAndSerialNumber(
      IssuerAndSerialNumber issuerAndSerialNumber) {
    return new OriginatorIdentifierOrKey(
        Args.notNull(issuerAndSerialNumber, "issuerAndSerialNumber"), null, null);
  }

  public static OriginatorIdentifierOrKey ofSubjectKeyIdentifier(
      Asn1OctetString subjectKeyIdentifier) {
    return new OriginatorIdentifierOrKey(null,
        Args.notNull(subjectKeyIdentifier, "subjectKeyIdentifier"), null);
  }

  public static OriginatorIdentifierOrKey ofOriginatorKey(OriginatorPublicKey originatorKey) {
    return new OriginatorIdentifierOrKey(null, null,
        Args.notNull(originatorKey, "originatorKey"));
  }

  public static OriginatorIdentifierOrKey fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1Sequence) {
      return ofIssuerAndSerialNumber(IssuerAndSerialNumber.fromAsn1((Asn1Sequence) asn1));
    } else if (asn1 instanceof Asn1TaggedObject) {
      Asn1TaggedObject t = (Asn1TaggedObject) asn1;
      int tagNo = t.getTagNo();
      if (tagNo == 0) {
        return ofSubjectKeyIdentifier(t.getImplicitOctetStringBase());
      } else if (tagNo == 1) {
        return ofOriginatorKey(OriginatorPublicKey.fromAsn1(t.getImplicitSequenceBase()));
      } else {
        throw CodecException.seqWithUnexpectedElements();
      }
    } else {
      throw CodecException.seqWithUnexpectedElements();
    }
  }

  public IssuerAndSerialNumber getIssuerAndSerialNumber() {
    return issuerAndSerialNumber;
  }

  public Asn1OctetString getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public OriginatorPublicKey getOriginatorKey() {
    return originatorKey;
  }

  public byte[] subjectKeyIdentifier() {
    return Asn1Util.fromAsn1(subjectKeyIdentifier);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    if (issuerAndSerialNumber != null) {
      return issuerAndSerialNumber.toAsn1Primitive();
    }

    if (subjectKeyIdentifier != null) {
      return Asn1TaggedObject.newImplicit(0, subjectKeyIdentifier);
    }

    return Asn1TaggedObject.newImplicit(1, originatorKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (issuerAndSerialNumber != null) {
      return issuerAndSerialNumber.toStringWithLineSep(buf, indentLevel, "issuerAndSerialNumber");
    }

    if (subjectKeyIdentifier != null) {
      return subjectKeyIdentifier.toStringWithLineSep(buf, indentLevel, "subjectKeyIdentifier");
    }

    return originatorKey.toStringWithLineSep(buf, indentLevel, "originatorKey");
  }
}
