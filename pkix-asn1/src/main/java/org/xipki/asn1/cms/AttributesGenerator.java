// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class AttributesGenerator {

  private final Map<Asn1Oid, Attribute> idAttrMap = new HashMap<>();

  private final List<Asn1Oid> ids = new LinkedList<>();

  public AttributesGenerator() {
  }

  public void addAttribute(Attribute attribute) throws GenerationException {
    Args.notNull(attribute, "attribute");
    Asn1Oid oid = attribute.getAttrType();
    boolean exists = ids.contains(oid);
    if (exists) {
      throw new GenerationException("attribute " + oid + " exists");
    }

    idAttrMap.put(oid, attribute);
    ids.add(oid);
  }

  public Attribute replaceExtension(Attribute attribute) {
    Args.notNull(attribute, "attribute");
    Asn1Oid oid = attribute.getAttrType();
    boolean exists = ids.contains(oid);
    Attribute oldEx = exists ? idAttrMap.remove(oid) : null;

    idAttrMap.put(oid, attribute);
    if (!exists) {
      ids.add(oid);
    }

    return oldEx;
  }

  public Attribute removeAttribute(Asn1Oid attributeType) {
    Args.notNull(attributeType, "attributeType");
    boolean exists = ids.remove(attributeType);
    return exists ? idAttrMap.remove(attributeType) : null;
  }

  public Attribute getAttribute(Asn1Oid attributeType) {
    return idAttrMap.get(attributeType);
  }

  public boolean hasAttributes() {
    return !ids.isEmpty();
  }

  public boolean hasAttribute(Asn1Oid extensionId) {
    return ids.contains(extensionId);
  }

  public Attribute.Set0 buildSet0() {
    return ids.isEmpty() ? new Attribute.Set0() : new Attribute.Set0(toAttributeArray());
  }

  public Attribute.Set1 buildSet1() throws CodecException {
    if (ids.isEmpty()) {
      throw new CodecException("no extension is present");
    }

    return new Attribute.Set1(toAttributeArray());
  }

  public Attribute.Seq1 buildSeq1() throws CodecException {
    if (ids.isEmpty()) {
      throw new CodecException("no extension is present");
    }

    return new Attribute.Seq1(toAttributeArray());
  }

  private Attribute[] toAttributeArray() {
    Attribute[] extns = new Attribute[ids.size()];
    int i = 0;
    for (Asn1Oid oid : ids) {
      extns[i++] = idAttrMap.get(oid);
    }
    return extns;
  }

}
