// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.ToStringUtil;

/**
 * The TypeOfBiometricData object.
 * <pre>
 * TypeOfBiometricData ::= CHOICE {
 *   predefinedBiometricType   PredefinedBiometricType,
 *   biometricDataOid          OBJECT IDENTIFIER }
 *
 * PredefinedBiometricType ::= INTEGER {
 *   picture(0),handwritten-signature(1)}
 *   (picture|handwritten-signature)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TypeOfBiometricData extends Asn1Encodable {

  public static final int PICTURE                     = 0;
  public static final int HANDWRITTEN_SIGNATURE       = 1;

  private final Asn1Integer predefinedBiometricType;

  private final Asn1Oid biometricDataOid;

  public static TypeOfBiometricData fromAsn1(Asn1Primitive obj) {
    Args.notNull(obj, "obj");

    if (obj instanceof Asn1Integer) {
      return TypeOfBiometricData.ofPredefinedBiometricType(
                ((Asn1Integer) obj).getValue().intValueExact());
    } else if (obj instanceof Asn1Oid) {
      return TypeOfBiometricData.ofBiometricData((Asn1Oid) obj);
    } else {
      throw new IllegalArgumentException("unknown object in getInstance");
    }
  }

  private TypeOfBiometricData(Asn1Integer predefinedBiometricType, Asn1Oid biometricDataOid) {
    this.predefinedBiometricType = predefinedBiometricType;
    this.biometricDataOid = biometricDataOid;
  }

  public static TypeOfBiometricData ofPredefinedBiometricType(int predefinedBiometricType) {
    if (predefinedBiometricType == PICTURE ||
        predefinedBiometricType == HANDWRITTEN_SIGNATURE) {
      return new TypeOfBiometricData(new Asn1Integer(predefinedBiometricType), null);
    } else {
        throw new IllegalArgumentException(
            "unknow PredefinedBiometricType : " + predefinedBiometricType);
    }
  }

  public static TypeOfBiometricData ofBiometricData(Asn1Oid biometricDataOid) {
    return new TypeOfBiometricData(null,
        Args.notNull(biometricDataOid, "biometricDataOid"));
  }

  public boolean isPredefined() {
    return predefinedBiometricType != null;
  }

  public Asn1Integer getPredefinedBiometricType() {
    return predefinedBiometricType;
  }

  public Asn1Oid getBiometricDataOid() {
    return biometricDataOid;
  }

  public Integer predefinedBiometricType() {
    return Asn1Util.fromAsn1Int(predefinedBiometricType);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return predefinedBiometricType != null
        ? predefinedBiometricType : biometricDataOid;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (predefinedBiometricType == null) {
      return biometricDataOid.toString(buf, indentLevel);
    }

    int type = predefinedBiometricType.getValue().intValue();
    String text = (type == PICTURE) ? "picture"
        : (type == HANDWRITTEN_SIGNATURE) ? "handwritten-signature"
        : Integer.toString(type);
    return ToStringUtil.appendIndent(buf, indentLevel, text);
  }
}
