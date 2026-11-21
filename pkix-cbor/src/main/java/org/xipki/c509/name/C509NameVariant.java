// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstCertificateType;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * A name in one of several encodings, selected by the certificate type
 * ({@link ConstCertificateType}).
 *
 * <pre>
 * NameVariant = [
 *   type:  int .ge 0 .le 255,
 *   value: Defined,
 * ]
 * </pre>
 * <ul>
 *   <li>type 0 (X509): the value is a bstr containing the DER-encoded X.509 Name.</li>
 *   <li>type 4 (C509): the value is a {@link C509Name}.</li>
 *   <li>other types: the value is kept as {@link CborEncodedItem}.</li>
 * </ul>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509NameVariant extends C509CborItem {

  private final int type;

  /**
   * byte[] for {@link ConstCertificateType#x509}, {@link C509Name} for
   * {@link ConstCertificateType#c509}, otherwise {@link CborEncodedItem}.
   */
  private final Object value;

  private C509NameVariant(int type, Object value) {
    this.type = type;
    this.value = value;
  }

  /**
   * @param derName the DER-encoded X.509 Name.
   */
  public static C509NameVariant ofX509(byte[] derName) {
    if (derName == null || derName.length == 0) {
      throw new IllegalArgumentException("derName must not be empty");
    }
    if ((derName[0] & 0xFF) != 0x30) {
      throw new IllegalArgumentException("derName is not a DER-encoded SEQUENCE");
    }
    return new C509NameVariant(ConstCertificateType.x509, derName.clone());
  }

  public static C509NameVariant ofC509(C509Name name) {
    return new C509NameVariant(ConstCertificateType.c509, Args.notNull(name, "name"));
  }

  /**
   * Creates a name of the given type.
   *
   * @param type  the type, between 0 and 255, see {@link ConstCertificateType}.
   * @param value byte[] for {@link ConstCertificateType#x509}, {@link C509Name} for
   *              {@link ConstCertificateType#c509}, otherwise a {@link CborEncodedItem}, or
   *              generic CBOR data, see {@link CborEncodedItem#ofData(Object)}.
   */
  public static C509NameVariant of(int type, Object value) {
    checkType(type);
    if (type == ConstCertificateType.x509) {
      if (!(value instanceof byte[])) {
        throw new IllegalArgumentException("value of type 0 must be byte[]");
      }
      return ofX509((byte[]) value);
    } else if (type == ConstCertificateType.c509) {
      if (!(value instanceof C509Name)) {
        throw new IllegalArgumentException("value of type 4 must be C509Name");
      }
      return ofC509((C509Name) value);
    }

    Args.notNull(value, "value");
    return new C509NameVariant(type, CborEncodedItem.ofData(value));
  }

  private static void checkType(long type) {
    if (type < 0 || type > 255) {
      throw new IllegalArgumentException("type out of range [0, 255]: " + type);
    }
  }

  /** The certificate type, see {@link ConstCertificateType}. */
  public int type() {
    return type;
  }

  /**
   * The DER-encoded X.509 Name if the type is {@link ConstCertificateType#x509}, otherwise null.
   */
  public byte[] x509Name() {
    return type == ConstCertificateType.x509 ? ((byte[]) value).clone() : null;
  }

  /** The C509 Name if the type is {@link ConstCertificateType#c509}, otherwise null. */
  public C509Name c509Name() {
    return type == ConstCertificateType.c509 ? (C509Name) value : null;
  }

  /** The value if the type is not X509 or C509, otherwise null. */
  public CborEncodedItem raw() {
    return (value instanceof CborEncodedItem) ? (CborEncodedItem) value : null;
  }

  /**
   * The value of any type: byte[] (a copy) for {@link ConstCertificateType#x509},
   * {@link C509Name} for
   * {@link ConstCertificateType#c509}, otherwise {@link CborEncodedItem}.
   */
  public Object value() {
    return (value instanceof byte[]) ? ((byte[]) value).clone() : value;
  }

  public static C509NameVariant read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    long type = in.readLong();
    if (type < 0 || type > 255) {
      throw new CodecException("NameVariant: type out of range [0, 255]: " + type);
    }

    try {
      if (type == ConstCertificateType.x509) {
        return ofX509(in.readByteString());
      } else if (type == ConstCertificateType.c509) {
        return ofC509(C509Name.read(in));
      } else {
        return new C509NameVariant((int) type, in.readEncodedItem());
      }
    } catch (IllegalArgumentException e) {
      throw new CodecException("NameVariant: " + e.getMessage(), e);
    }
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    out.writeLong(type);
    if (value instanceof byte[]) {
      out.writeByteString((byte[]) value);
    } else if (value instanceof C509Name) {
      ((C509Name) value).encode(out);
    } else {
      ((CborEncodedItem) value).encode(out);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("type", ConstCertificateType.describe(type));
    if (type == ConstCertificateType.c509) {
      out.external("value", (C509Name) value);
    } else if (value instanceof byte[]) {
      out.hex("value", (byte[]) value);
    } else {
      out.kv("value", ((CborEncodedItem) value).toDiagnostic());
    }
  }

}
