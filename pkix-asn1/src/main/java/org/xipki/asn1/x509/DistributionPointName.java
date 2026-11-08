// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.RDN;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * The DistributionPointName object.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * DistributionPointName ::= CHOICE {
 *     fullName                 [0] GeneralNames,
 *     nameRelativeToCRLIssuer  [1] RDN
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DistributionPointName extends Asn1Encodable {

  public static final int tag_fullName = 0;

  public static final int tag_nameRelativeToCRLIssuer = 1;

  private final int tagNo;

  private final GeneralNames fullName;

  private final RDN nameRelativeToCRLIssuer;

  private DistributionPointName(GeneralNames fullName, RDN nameRelativeToCRLIssuer) {
    this.fullName = fullName;
    this.nameRelativeToCRLIssuer = nameRelativeToCRLIssuer;

    this.tagNo = (fullName != null) ? tag_fullName : tag_nameRelativeToCRLIssuer;
  }

  public static DistributionPointName ofName(GeneralNames name) {
    return new DistributionPointName(Args.notNull(name, "name"), null);
  }

  public static DistributionPointName ofNameRelativeToCRLIssuer(RDN nameRelativeToCRLIssuer) {
    return new DistributionPointName(null,
        Args.notNull(nameRelativeToCRLIssuer, "nameRelativeToCRLIssuer"));
  }

  public static DistributionPointName fromAsn1(Asn1TaggedObject obj) throws CodecException {
    int tagNo = obj.getTagNo();
    if (tagNo == 0) {
      return ofName(GeneralNames.fromAsn1(obj.getImplicitSequenceBase()));
    } else if (tagNo == 1) {
      return ofNameRelativeToCRLIssuer(RDN.fromAsn1(obj.getImplicitSetBase()));
    } else {
      throw new IllegalArgumentException("unknown tag: " + tagNo);
    }
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return fullName != null
        ? Asn1TaggedObject.newImplicit(0, fullName)
        : Asn1TaggedObject.newImplicit(1, nameRelativeToCRLIssuer);
  }

  public int getTagNo() {
    return tagNo;
  }

  public GeneralNames getFullName() {
    return fullName;
  }

  public RDN getNameRelativeToCRLIssuer() {
    return nameRelativeToCRLIssuer;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (fullName != null) {
      fullName.toStringWithLineSep(buf, indentLevel, "fullName");
    } else {
      nameRelativeToCRLIssuer.toStringWithLineSep(buf, indentLevel, "nameRelativeToCRLIssuer");
    }
    return buf;
  }
}
