// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * A type identifier together with an opaque value, used for the otherName and
 * hardwareModuleName general names (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * OtherName = [
 *   type-id: ~oid,
 *   value:   bytes,
 * ]
 * HardwareModuleName = [
 *   hwType:      ~oid,
 *   hwSerialNum: bytes,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509OtherName extends C509CborItem {

  private final C509ObjectId typeId;

  private final byte[] value;

  public C509OtherName(C509ObjectId typeId, byte[] value) {
    this.typeId = Args.notNull(typeId, "typeId");
    if (value == null || value.length == 0) {
      throw new IllegalArgumentException("value must not be empty");
    }
    this.value = value.clone();
  }

  public C509ObjectId typeId() {
    return typeId;
  }

  public byte[] value() {
    return value.clone();
  }

  public static C509OtherName read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    return new C509OtherName(C509ObjectId.read(in), in.readByteString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    typeId.encode(out);
    out.writeByteString(value);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("type", typeId).hex("value", value);
  }

}
