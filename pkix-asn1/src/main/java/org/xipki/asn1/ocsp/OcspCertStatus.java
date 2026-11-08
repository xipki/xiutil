// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 *  CertStatus ::= CHOICE {
 *      good        [0]     IMPLICIT NULL,
 *      revoked     [1]     IMPLICIT RevokedInfo,
 *      unknown     [2]     IMPLICIT UnknownInfo }
 *
 * UnknownInfo ::= NULL
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OcspCertStatus extends Asn1Encodable {

  public static final OcspCertStatus GOOD = new OcspCertStatus(0, null);

  public static final OcspCertStatus UNKNOWN = new OcspCertStatus(2, null);

  private final int tagNo;
  private final RevokedInfo revoked;

  private OcspCertStatus(int tagNo, RevokedInfo revoked) {
    this.tagNo = tagNo;
    this.revoked = revoked;
  }

  public static OcspCertStatus ofRevoked(RevokedInfo info) {
    return new OcspCertStatus(1, Args.notNull(info, "info"));
  }

  public static OcspCertStatus fromAsn1(Asn1TaggedObject choice) throws CodecException {
    int tagNo = choice.getTagNo();
    if (tagNo == 0) {
      return GOOD;
    } else if (tagNo == 2) {
      return UNKNOWN;
    } else if (tagNo == 1) {
      return ofRevoked(RevokedInfo.fromAsn1(choice.getImplicitSequenceBase()));
    } else {
      throw new CodecException("unknown tag " + tagNo);
    }
  }

  public int getTagNo() {
    return tagNo;
  }

  public RevokedInfo getRevoked() {
    return revoked;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    if (revoked != null) {
      return Asn1TaggedObject.newImplicit(1, revoked);
    } else {
      return Asn1TaggedObject.newImplicit(tagNo, Asn1Null.INSTANCE);
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (revoked != null) {
      return revoked.toStringWithLineSep(buf, indentLevel, "revoked");
    }

    return ToStringUtil.appendIndent(buf, indentLevel,
        (tagNo == 0) ? "good" : (tagNo == 2) ? "unknown" : "tag " + tagNo);
  }
}
