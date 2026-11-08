// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * TCGCredentialType::= SEQUENCE {
 *     certificateType CredentialType}
 *
 * CredentialType ::= OBJECT IDENTIFIER (tcg-kp-PlatformAttributeCertificate |
 *     tcg-kp-PlatformKeyCertificate |
 *     tcg-kp-AdditionalPlatformAttributeCertificate |
 *     tcg-kp-AdditionalPlatformKeyCertificate |
 *     tcg-kp-DeltaPlatformAttributeCertificate |
 *     tcg-kp-DeltaPlatformKeyCertificate )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGCredentialType extends Asn1Encodable {

  private final Asn1Oid certificateType;

  public TCGCredentialType(Asn1Oid certificateType) {
    this.certificateType = Args.notNull(certificateType, "certificateType");

    if (!(TcgOIDs.tcg_kp_PlatformAttributeCertificate.equals(certificateType) ||
        TcgOIDs.tcg_kp_PlatformKeyCertificate.equals(certificateType) ||
        TcgOIDs.tcg_kp_AdditionalPlatformAttributeCertificate.equals(certificateType) ||
        TcgOIDs.tcg_kp_DeltaPlatformAttributeCertificate.equals(certificateType) ||
        TcgOIDs.tcg_kp_DeltaPlatformKeyCertificate.equals(certificateType))) {
      throw new IllegalArgumentException("invalid certificateType " + certificateType.getId());
    }
  }

  public Asn1Oid getCertificateType() {
    return certificateType;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(certificateType);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certificateType.toStringNoLineSep(buf, indentLevel, "certificateType", true);

    return deleteLastNewLine(buf);
  }

  public static TCGCredentialType fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 1);
    Asn1Oid type = seq.getOidAt(0);
    return new TCGCredentialType(type);
  }

}
