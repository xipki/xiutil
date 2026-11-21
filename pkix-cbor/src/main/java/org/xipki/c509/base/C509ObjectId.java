// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.base;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * An ASN.1 object identifier, carried in CBOR as the byte string of its DER content octets.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ObjectId extends C509CborItem implements Comparable<C509ObjectId> {

  private final Asn1Oid oid;

  private C509ObjectId(Asn1Oid oid) {
    this.oid = Args.notNull(oid, "oid");
  }

  public static C509ObjectId of(String dotted) {
    return new C509ObjectId(new Asn1Oid(Args.notNull(dotted, "dotted")));
  }

  public static C509ObjectId of(Asn1Oid oid) {
    return new C509ObjectId(oid);
  }

  public static C509ObjectId ofContentOctets(byte[] octets) {
    return new C509ObjectId(new Asn1Oid(Args.notNull(octets, "octets")));
  }

  public Asn1Oid asn1() {
    return oid;
  }

  public String dotted() {
    return oid.getId();
  }

  public static C509ObjectId read(CborDecoder in) throws CodecException {
    CborType type = in.peekType();
    if (!type.isByteString()) {
      throw new CodecException("object identifier: expected byte string, got " + type);
    }
    return ofContentOctets(in.readByteString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeByteString(oid.getOctets());
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(dotted());
  }

  @Override
  public int compareTo(C509ObjectId other) {
    return dotted().compareTo(other.dotted());
  }

  @Override
  public String toString() {
    return dotted();
  }

}
