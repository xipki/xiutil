// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.cms.IssuerAndSerialNumber;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 9883:
 * <pre>
 *    id-at-statementOfPossession OBJECT IDENTIFIER ::=
 *      { 1 3 6 1 4 1 22112 2 1 }
 *
 *    privateKeyPossessionStatement ATTRIBUTE ::= {
 *      TYPE PrivateKeyPossessionStatement
 *      IDENTIFIED BY id-at-statementOfPossession }
 *
 *    PrivateKeyPossessionStatement ::= SEQUENCE {
 *      signer  IssuerAndSerialNumber,
 *      cert    Certificate OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PrivateKeyPossessionStatement extends Asn1Encodable {

  private final IssuerAndSerialNumber signer;

  private final Certificate cert;

  public PrivateKeyPossessionStatement(IssuerAndSerialNumber signer, Certificate cert) {
    this.signer = Args.notNull(signer, "signer");
    this.cert = cert;
  }

  public static PrivateKeyPossessionStatement fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    IssuerAndSerialNumber signer = IssuerAndSerialNumber.fromAsn1(seq.getSequenceAt(0));
    Certificate cert = size == 1 ? null : Certificate.fromAsn1(seq.getSequenceAt(1));
    return new PrivateKeyPossessionStatement(signer, cert);
  }

  public static PrivateKeyPossessionStatement fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public IssuerAndSerialNumber getSigner() {
    return signer;
  }

  public Certificate getCert() {
    return cert;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(signer, cert);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    signer.toStringWithLineSep(buf, indentLevel, "signer", true);

    if (cert != null) {
      cert.toStringWithLineSep(buf, indentLevel, "cert", true);
    }

    return deleteLastNewLine(buf);
  }

}
