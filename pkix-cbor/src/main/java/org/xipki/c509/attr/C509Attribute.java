// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509Catalog;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * One attribute of a certification request (draft-ietf-cose-cbor-encoded-cert-21, Section 4.1).
 *
 * <pre>
 * CRAttribute = (
 *   ( attributeType: int, attributeValue: Defined ) //
 *   ( attributeType: ~oid, attributeValue: bytes )
 * )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Attribute extends C509CborItem implements Comparable<C509Attribute> {

  static final C509Catalog<C509AttrValue> CATALOG = new
      C509Catalog<C509AttrValue>(C509RawAttrValue::read,
      ConstAttributeType::describe)
      .bind(C509ChallengePassword.class, C509ChallengePassword::read,
          ConstAttributeType.challengePassword)
      .bind(C509ExtensionRequest.class, C509ExtensionRequest::read,
          ConstAttributeType.extensionRequest)
      .bind(C509PrivateKeyPossessionStatement.class, C509PrivateKeyPossessionStatement::read,
          ConstAttributeType.privateKeyPossessionStatement)
      .bind(C509ChangeSubjectName.class, C509ChangeSubjectName::read,
          ConstAttributeType.changeSubjectName)
      .bind(C509DateOfBirth.class, C509DateOfBirth::read, ConstAttributeType.dateOfBirth)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.placeOfBirth)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.gender)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.countryOfCitizenship)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.countryOfResidence);

  private final long type;

  private final C509AttrValue value;

  /**
   * @param type  the attribute type, see {@link ConstAttributeType}.
   * @param value the value. A value of a foreign class is converted to the class bound to the
   *              type, provided its encoding fits.
   */
  public C509Attribute(long type, C509AttrValue value) {
    this.type = type;
    this.value = CATALOG.adopt(type, value);
  }

  public long type() {
    return type;
  }

  public C509AttrValue value() {
    return value;
  }

  public <T extends C509AttrValue> T value(Class<T> clazz) {
    return clazz.cast(value);
  }

  public static C509Attribute read(CborDecoder in) throws CodecException {
    long type = in.readLong();
    return new C509Attribute(type, CATALOG.read(type, in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(type);
    out.writeObject(value);
  }

  @Override
  protected void render(C509TextTree out) {
    out.item(ConstAttributeType.describe(type), value);
  }

  @Override
  public int compareTo(C509Attribute other) {
    return Long.compare(type, other.type);
  }

}
