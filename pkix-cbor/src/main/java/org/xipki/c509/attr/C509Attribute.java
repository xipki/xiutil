// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509Catalog;
import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

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
      .bind(C509TextAttrValue.class, C509TextAttrValue::read, ConstAttributeType.placeOfBirth)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read, ConstAttributeType.gender)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.countryOfCitizenship)
      .bind(C509TextAttrValue.class, C509TextAttrValue::read,
          ConstAttributeType.countryOfResidence);

  private final long type;

  private final C509AttrValue value;

  /**
   * Registers the value class of attribute types not known to this library, so that they are
   * decoded into {@code clazz} instead of {@link C509RawAttrValue}. Register before the first
   * attribute of these types is decoded or created, e.g. at application start-up. To give the
   * types a name, use {@link ConstAttributeType#register(long, String)}.
   *
   * @param <T>   the value class.
   * @param clazz the value class.
   * @param reader reads the value from the CBOR stream, usually {@code MyValue::read}.
   * @param types the attribute types.
   * @throws IllegalStateException if one of the types is already registered; then none of the
   *         types is registered.
   */
  public static <T extends C509AttrValue> void register(
      Class<T> clazz, C509Cbor.Reader<T> reader, long... types) {
    Args.notNull(clazz, "clazz");
    Args.notNull(reader, "reader");
    if (types == null || types.length == 0) {
      throw new IllegalArgumentException("types must not be empty");
    }
    CATALOG.bind(clazz, reader, types);
  }

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
