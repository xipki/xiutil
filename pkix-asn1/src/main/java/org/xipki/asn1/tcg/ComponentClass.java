// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * ComponentClass ::= SEQUENCE {
 *     componentClassRegistry ComponentClassRegistry,
 *     componentClassValue    OCTET STRING (SIZE(4))
 * }
 *
 * ; tcg-registry-componentClass-storage is renamed to tcg-registry-componentClass-disk.
 * ComponentClassRegistry ::= OBJECT IDENTIFIER ( tcg-registry-componentClass-tcg
 *                 | tcg-registry-componentClass-dmtf
 *                 | tcg-registry-componentClass-pcie
 *                 | tcg-registry-componentClass-disk )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentClass extends Asn1Encodable {

  private final Asn1Oid componentClassRegistry;

  private final Asn1OctetString componentClassValue;

  public ComponentClass(Asn1Oid componentClassRegistry, byte[] componentClassValue) {
    this(componentClassRegistry, Asn1Util.toOctetString(componentClassValue));
  }

  public ComponentClass(Asn1Oid componentClassRegistry, Asn1OctetString componentClassValue) {
    this.componentClassRegistry = Args.notNull(componentClassRegistry, "componentClassRegistry");
    this.componentClassValue = Args.notNull(componentClassValue, "componentClassValue");
    Args.equals(componentClassValue.getOctetsLength(), "componentClassValue.length", 4);

    if (!(TcgOIDs.tcg_registry_componentClass_tcg.equals(componentClassRegistry) ||
        TcgOIDs.tcg_registry_componentClass_dmtf.equals(componentClassRegistry) ||
        TcgOIDs.tcg_registry_componentClass_pcie.equals(componentClassRegistry) ||
        TcgOIDs.tcg_registry_componentClass_disk.equals(componentClassRegistry))) {
      throw new IllegalArgumentException(
          "invalid componentClassRegistry " + componentClassRegistry.getId());
    }
  }

  public Asn1Oid getComponentClassRegistry() {
    return componentClassRegistry;
  }

  public Asn1OctetString getComponentClassValue() {
    return componentClassValue;
  }

  public byte[] componentClassValue() {
    return componentClassValue.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(componentClassRegistry, componentClassValue);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    componentClassRegistry.toStringNoLineSep(buf, indentLevel, "componentClassRegistry", true);
    componentClassValue.toStringWithLineSep(buf, indentLevel, "componentClassValue", true);

    return deleteLastNewLine(buf);
  }

  public static ComponentClass fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new ComponentClass(seq.getOidAt(0), seq.getOctetStringAt(1));
  }

}
