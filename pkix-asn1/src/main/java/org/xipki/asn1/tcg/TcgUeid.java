// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Defined in
 * https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf
 *
 * 6.1.4 UEID Extension
 * This extension contains a UEID [9] that identifies the device containing
 * the private key and is identified by the ertificate’s subjectPublicKey. In
 * the case of its inclusion as a CRL extension, the device containing the
 * private key is identified by the certificate serial number, which
 * identifies the certificate containing the subjectPublicKey.
 *
 * The OID declaration of DiceUeid is as follows:
 * <pre>
 * tcg-dice-Ueid OBJECT IDENTIFIER ::= {tcg-dice ueid(4) }
 * </pre>
 *
 * The ASN.1 definition is as follows:
 *
 * <pre>
 * TcgUeid ::= SEQUENCE {
 *     ueid OCTET STRING
 * }
 * </pre>
 *
 * When filling in the UEID extension, the issuer must ensure that the content
 * of this extension contributes to the CDI which generated the subject key
 * (such that a change in the field value will cause a change in the CDI).
 *
 * @author Lijun Liao (xipki)
 */
public class TcgUeid extends Asn1Encodable {

  private final Asn1OctetString ueid;

  public TcgUeid(byte[] ueid) {
    this(Asn1Util.toOctetString(ueid));
  }

  public TcgUeid(Asn1OctetString ueid) {
    this.ueid = Args.notEmptyBytes(ueid, "ueid");
  }

  public Asn1OctetString getUeid() {
    return ueid;
  }

  public byte[] ueid() {
    return ueid.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(ueid);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (ueid != null) {
      ueid.toStringWithLineSep(buf, indentLevel, "ueid", true);
    }

    return deleteLastNewLine(buf);
  }

  public static TcgUeid fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 1);
    return new TcgUeid(seq.getOctetStringAt(0));
  }

}
