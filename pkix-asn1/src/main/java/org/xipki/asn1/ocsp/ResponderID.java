// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.Objects;

/**
 * <pre>
 * ResponderID ::= CHOICE {
 *      byName          [1] Name,
 *      byKey           [2] KeyHash }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ResponderID extends Asn1Encodable {

  private final X500Name byName;

  private final Asn1OctetString byKey;

  public static ResponderID fromAsn1(Asn1TaggedObject id) throws CodecException {
    Args.notNull(id, "id");
    int tagNo = id.getTagNo();
    if (tagNo == 1) {
      return ofByName(X500Name.fromAsn1(id.getExplicitSequenceBase()));
    } else if (tagNo == 2) {
      return ofByKey(id.getExplicitOctetStringBase());
    } else {
      throw new CodecException("unknown tag " + tagNo);
    }
  }

  private ResponderID(X500Name byName, Asn1OctetString byKey) {
    this.byName = byName;
    this.byKey = byKey;
  }

  public static ResponderID ofByKey(Asn1OctetString byKey) {
    return new ResponderID(null, Args.notNull(byKey, "byKey"));
  }

  public static ResponderID ofByKey(byte[] byKey) {
    return new ResponderID(null, new Asn1OctetString(Args.notNull(byKey, "byKey")));
  }

  public static ResponderID ofByName(X500Name byName) {
    return new ResponderID(Args.notNull(byName, "byName"), null);
  }

  public Asn1OctetString getByKey() {
    return byKey;
  }

  public X500Name getByName() {
    return byName;
  }

  public byte[] byKey() {
    return Asn1Util.fromAsn1(byKey);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return byName != null ? Asn1TaggedObject.newExplicit(1, byName)
        : Asn1TaggedObject.newExplicit(2, byKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (byName != null) {
      return byName.toStringNoLineSep(buf, indentLevel, "byName");
    }

    return byKey.toStringWithLineSep(buf, indentLevel, "byKey");
  }

  @Override
  public int hashCode() {
    return byName != null ? byName.hashCode() : byKey.hashCode();
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof ResponderID)) {
      return false;
    }

    ResponderID b = (ResponderID) obj;
    return Objects.equals(byName, b.byName)
        && Objects.equals(byKey, b.byKey);
  }

}
