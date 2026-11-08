// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.cmp.PBMParameter;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.CmpOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * PKMACValue ::= SEQUENCE {
 *      algId  AlgorithmIdentifier,
 *      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
 *      -- parameter value is PBMParameter
 *      value  BIT STRING }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKMACValue extends Asn1Encodable {

  private final AlgorithmIdentifier  algId;
  private final Asn1BitString value;

  public static PKMACValue fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier algId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1BitString value = seq.getBitStringAt(1);
    return new PKMACValue(algId, value);
  }

  /**
   * Creates a new PKMACValue.
   * @param params parameters for password-based MAC
   * @param value MAC of the DER-encoded SubjectPublicKeyInfo
   */
  public PKMACValue(PBMParameter params, Asn1BitString value) {
    this(new AlgorithmIdentifier(
        CmpOIDs.passwordBasedMac,
        Args.notNull(params, "params").toAsn1Primitive()), value);
  }

  /**
   * Creates a new PKMACValue.
   * @param aid CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter
   * @param value MAC of the DER-encoded SubjectPublicKeyInfo
   */
  public PKMACValue(AlgorithmIdentifier aid, Asn1BitString value) {
    this.algId = Args.notNull(aid, "aid");
    this.value = Args.notNull(value, "value");
  }

  public AlgorithmIdentifier getAlgId() {
    return algId;
  }

  public Asn1BitString getValue() {
    return value;
  }

  public byte[] value() {
    return value.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(algId, value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    algId.toStringWithLineSep(buf, indentLevel, "algId", true);
    value.toStringWithLineSep(buf, indentLevel, "value", true);

    return deleteLastNewLine(buf);
  }

}
