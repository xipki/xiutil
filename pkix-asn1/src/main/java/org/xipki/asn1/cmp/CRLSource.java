// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.x509.DistributionPointName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <p>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * CRLSource ::= CHOICE {
 *     dpn          [0] DistributionPointName,
 *     issuer       [1] GeneralNames }
 * <p>
 *
 * @author Lijun Liao (xipki)
 */
public class CRLSource extends Asn1Encodable {

  private final DistributionPointName dpn;
  private final GeneralNames issuer;

  public static CRLSource fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    int tagNo = asn1.getTagNo();
    if (tagNo == 0) {
      return ofDpn(DistributionPointName.fromAsn1(asn1.getExplicitTaggedBase()));
    } else if (tagNo == 1) {
      return ofIssuer(GeneralNames.fromAsn1(asn1.getExplicitSequenceBase()));
    } else {
      throw new IllegalArgumentException("unknown tag " + tagNo);
    }
  }

  private CRLSource(DistributionPointName dpn, GeneralNames issuer) {
    this.dpn = dpn;
    this.issuer = issuer;
  }

  public static CRLSource ofDpn(DistributionPointName dpn) {
    return new CRLSource(Args.notNull(dpn, "dpn"), null);
  }

  public static CRLSource ofIssuer(GeneralNames issuer) {
    return new CRLSource(null, Args.notNull(issuer, "issuer"));
  }

  public DistributionPointName getDpn() {
    return dpn;
  }

  public GeneralNames getIssuer() {
    return issuer;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return dpn != null ? Asn1TaggedObject.newExplicit(0, dpn)
        : Asn1TaggedObject.newExplicit(1, issuer);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (dpn != null) {
      return dpn.toStringWithLineSep(buf, indentLevel, "dpn");
    }

    return issuer.toStringWithLineSep(buf, indentLevel, "issuer");
  }
}
