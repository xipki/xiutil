// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * The SubjectKeyIdentifier object.
 * <pre>
 * SubjectKeyIdentifier::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectKeyIdentifier extends Asn1Encodable {

  private final byte[] keyidentifier;

  public SubjectKeyIdentifier(byte[] keyid) {
    this.keyidentifier = Args.notEmpty(keyid, "keyId");
  }

  public static SubjectKeyIdentifier fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1OctetString.fromEncoded(encoded));
  }

  public static SubjectKeyIdentifier fromAsn1(Asn1OctetString keyid) {
    return new SubjectKeyIdentifier(keyid.getOctets());
  }

  public byte[] getKeyIdentifier() {
    return keyidentifier;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1OctetString(keyidentifier);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendHex(buf, indentLevel, keyidentifier);
  }

}
