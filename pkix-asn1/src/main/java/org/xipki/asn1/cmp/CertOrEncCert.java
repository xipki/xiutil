// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.EncryptedKey;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 9810:
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * CertOrEncCert ::= CHOICE {
 *     certificate     [0] CMPCertificate,
 *     encryptedCert   [1] EncryptedKey
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertOrEncCert extends Asn1Encodable {

  private final CMPCertificate certificate;
  private final EncryptedKey encryptedCert;

  public static CertOrEncCert fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1TaggedObject.fromEncoded(encoded));
  }

  public static CertOrEncCert fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    int tagNo = asn1.getTagNo();

    CMPCertificate certificate = null;
    EncryptedKey encryptedCert = null;
    if (tagNo == 0) {
      certificate = CMPCertificate.fromAsn1(asn1.getExplicitSequenceBase());
    } else if (tagNo == 1) {
      encryptedCert = EncryptedKey.fromAsn1(asn1.getExplicitBase());
    } else {
      throw new IllegalArgumentException("unknown tag: " + tagNo + " for CertOrEncCert");
    }
    return new CertOrEncCert(certificate, encryptedCert);
  }

  public static CertOrEncCert ofCertificate(CMPCertificate certificate) {
    return new CertOrEncCert(Args.notNull(certificate, "certificate"), null);
  }

  public static CertOrEncCert ofEncryptedCert(EncryptedKey encryptedCert) {
    return new CertOrEncCert(null, Args.notNull(encryptedCert, "encryptedCert"));
  }

  private CertOrEncCert(CMPCertificate certificate, EncryptedKey encryptedCert) {
    this.certificate = certificate;
    this.encryptedCert = encryptedCert;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  public CMPCertificate getCertificate() {
    return certificate;
  }

  public EncryptedKey getEncryptedCert() {
    return encryptedCert;
  }

  public boolean hasCertificate() {
    return certificate != null;
  }

  public boolean hasEncryptedCert() {
    return encryptedCert != null;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return certificate != null ? Asn1TaggedObject.newExplicit(0, certificate)
        : Asn1TaggedObject.newExplicit(1, encryptedCert);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return certificate != null
        ? certificate.toStringWithLineSep(buf, indentLevel, "certificate")
        : encryptedCert.toStringWithLineSep(buf, indentLevel, "encryptedCert");
  }
}
