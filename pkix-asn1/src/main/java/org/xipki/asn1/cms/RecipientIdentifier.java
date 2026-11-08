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
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * RecipientIdentifier ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RecipientIdentifier extends Asn1Encodable {

  private final IssuerAndSerialNumber issuerAndSerialNumber;

  private final Asn1OctetString subjectKeyIdentifier;

  public static RecipientIdentifier fromAsn1(Asn1Primitive id) throws CodecException {
    Args.notNull(id, "id");
    if (id instanceof Asn1Sequence) {
      return ofIssuerAndSerialNumber(IssuerAndSerialNumber.fromAsn1((Asn1Sequence) id));
    } else if (id instanceof Asn1TaggedObject && id.getTagNo() == 0) {
      return ofSubjectKeyIdentifier(id.asTagged().getImplicitOctetStringBase());
    } else {
      throw new CodecException("unknown id " + id);
    }
  }

  private RecipientIdentifier(IssuerAndSerialNumber issuerAndSerialNumber,
                             Asn1OctetString subjectKeyIdentifier) {
    this.issuerAndSerialNumber = issuerAndSerialNumber;
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public static RecipientIdentifier ofSubjectKeyIdentifier(Asn1OctetString subjectKeyIdentifier) {
    return new RecipientIdentifier(null,
        Args.notNull(subjectKeyIdentifier, "subjectKeyIdentifier"));
  }

  public static RecipientIdentifier ofSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
    return ofSubjectKeyIdentifier(Asn1Util.toOctetString(subjectKeyIdentifier));
  }

  public static RecipientIdentifier ofIssuerAndSerialNumber(
      IssuerAndSerialNumber issuerAndSerialNumber) {
    return new RecipientIdentifier(
        Args.notNull(issuerAndSerialNumber, "issuerAndSerialNumber"), null);
  }

  public Asn1OctetString getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public IssuerAndSerialNumber getIssuerAndSerialNumber() {
    return issuerAndSerialNumber;
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
    return issuerAndSerialNumber != null ? issuerAndSerialNumber.toAsn1Primitive()
        : Asn1TaggedObject.newImplicit(0, subjectKeyIdentifier);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (issuerAndSerialNumber != null) {
      return issuerAndSerialNumber.toStringWithLineSep(buf, indentLevel, "issuerAndSerialNumber");
    }

    return subjectKeyIdentifier.toStringWithLineSep(buf, indentLevel, "subjectKeyIdentifier");
  }
}
