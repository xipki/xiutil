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
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.3">RFC 5652</a>:
 * Identify who signed the containing {@link SignerInfo} object.
 * <p>
 * The certificates referred to by this are at containing {@link SignedData} structure.
 * <p>
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * SignerIdentifier ::= CHOICE {
 *     issuerAndSerialNumber     IssuerAndSerialNumber,
 *     subjectKeyIdentifier  [0] SubjectKeyIdentifier
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SignerIdentifier extends Asn1Encodable {

  private final IssuerAndSerialNumber issuerAndSerialNumber;

  private final Asn1OctetString subjectKeyIdentifier;

  private SignerIdentifier(IssuerAndSerialNumber issuerAndSerialNumber,
                          Asn1OctetString subjectKeyIdentifier) {
    this.issuerAndSerialNumber = issuerAndSerialNumber;
    this.subjectKeyIdentifier = subjectKeyIdentifier;
  }

  public static SignerIdentifier ofIssuerAndSerialNumber(
      IssuerAndSerialNumber issuerAndSerialNumber) {
    return new SignerIdentifier(
        Args.notNull(issuerAndSerialNumber, "issuerAndSerialNumber"), null);
  }

  public static SignerIdentifier ofSubjectKeyIdentifier(Asn1OctetString subjectKeyIdentifier) {
    return new SignerIdentifier(null,
        Args.notNull(subjectKeyIdentifier, "subjectKeyIdentifier"));
  }

  public static SignerIdentifier fromAsn1(Asn1Primitive sid) throws CodecException {
    if (sid instanceof Asn1Sequence) {
      return ofIssuerAndSerialNumber(IssuerAndSerialNumber.fromAsn1((Asn1Sequence) sid));
    } else if (sid instanceof Asn1TaggedObject) {
      Asn1TaggedObject t = (Asn1TaggedObject) sid;
      if (t.getTagNo() == 0) {
        return ofSubjectKeyIdentifier(t.getImplicitOctetStringBase());
      }
    }

    throw new CodecException("invalid sid: " + sid);
  }

  public IssuerAndSerialNumber getIssuerAndSerialNumber() {
    return issuerAndSerialNumber;
  }

  public Asn1OctetString getSubjectKeyIdentifier() {
    return subjectKeyIdentifier;
  }

  public byte[] subjectKeyIdentifier() {
    return Asn1Util.fromAsn1(subjectKeyIdentifier);
  }

  public boolean hasSubjectKeyIdentifier() {
    return subjectKeyIdentifier != null;
  }

  public boolean isTagged() {
    return issuerAndSerialNumber == null;
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
