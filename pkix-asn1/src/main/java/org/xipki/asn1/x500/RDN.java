// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x500;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.exception.CodecException;

import java.util.List;
import java.util.Set;

/**
 * <pre>
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RDN extends AttributeTypeAndValue.Set1 {

  public RDN(AttributeTypeAndValue... entries) {
    super(entries);
  }

  public RDN(List<AttributeTypeAndValue> entries) {
    super(entries);
  }

  private RDN(Asn1Set set) throws CodecException {
    super(set);
  }

  public static RDN fromAsn1(Asn1Set set) throws CodecException {
    return new RDN(set);
  }

  /**
   * Create a single valued RDN.
   *
   * @param oid RDN type.
   * @param value RDN value.
   */
  public RDN(Asn1Oid oid, Asn1Primitive value) {
    super(new AttributeTypeAndValue(oid, value));
  }

  public boolean isMultiValued() {
    return entries.size() > 1;
  }

  /**
   * Return the number of AttributeTypeAndValue objects in this RDN,
   *
   * @return size of RDN, greater than 1 if multi-valued.
   */
  @Override
  public int size() {
    return entries.size();
  }

  public AttributeTypeAndValue getFirst() {
    return entries.isEmpty() ? null : entries.get(0);
  }

  void collectAttributeTypes(Set<Asn1Oid> oids) {
    for (AttributeTypeAndValue value : entries) {
      oids.add(value.getType());
    }
  }

  boolean containsAttributeType(Asn1Oid attributeType) {
    for (AttributeTypeAndValue attr : entries) {
      if (attr.getType().equals(attributeType)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Set(entries);
  }

  @Override
  public int hashCode() {
    return entries.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof RDN)) {
      return false;
    }

    RDN b = (RDN) obj;
    return entries.equals(b.entries);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    int size = entries.size();
    for (int i = 0; i < size; i++) {
      if (i != 0) {
        buf.append("/");
      }

      AttributeTypeAndValue atv = entries.get(i);
      Asn1Oid type = atv.getType();
      String name = X500Name.getName(type);
      if (name == null) {
        name = type.getId();
      }
      buf.append(name).append("=").append(atv.getValue());
    }
    return buf.toString();
  }

}
