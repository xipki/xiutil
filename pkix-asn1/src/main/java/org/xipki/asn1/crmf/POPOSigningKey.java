// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 4211:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * POPOSigningKey ::= SEQUENCE {
 *     poposkInput           [0] POPOSigningKeyInput OPTIONAL,
 *     algorithmIdentifier   AlgorithmIdentifier,
 *     signature             BIT STRING }
 *
 *  -- The signature (using "algorithmIdentifier") is on the
 *  -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
 *  -- certReq CertTemplate contains the subject and publicKey values,
 *  -- then poposkInput MUST be omitted and the signature MUST be
 *  -- computed on the DER-encoded value of CertReqMsg certReq.  If
 *  -- the CertReqMsg certReq CertTemplate does not contain the public
 *  -- key and subject values, then poposkInput MUST be present and
 *  -- MUST be signed.  This strategy ensures that the public key is
 *  -- not present in both the poposkInput and CertReqMsg certReq
 *  -- CertTemplate fields.
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class POPOSigningKey extends Asn1Encodable {

  private final POPOSigningKeyInput poposkInput;
  private final AlgorithmIdentifier algorithmIdentifier;
  private final Asn1BitString signature;

  public static POPOSigningKey fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    int index = 0;
    POPOSigningKeyInput poposkInput = seq.isNotTaggedAt(index, 0) ? null
        : POPOSigningKeyInput.fromAsn1(seq.getTaggedAt(index++).getImplicitSequenceBase());

    AlgorithmIdentifier algorithmIdentifier =
        AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));
    Asn1BitString signature = seq.getBitStringAt(index++);

    Asn1Util.checkSequenceEnd(index, size);
    return new POPOSigningKey(poposkInput, algorithmIdentifier, signature);
  }

  public POPOSigningKey(POPOSigningKeyInput poposkIn,
                        AlgorithmIdentifier aid, Asn1BitString signature) {
    this.poposkInput = poposkIn;
    this.algorithmIdentifier = Args.notNull(aid, "aid");
    this.signature = Args.notNull(signature, "signature");
  }

  public POPOSigningKey(POPOSigningKeyInput poposkIn, AlgorithmIdentifier aid, byte[] signature) {
    this(poposkIn, aid, Asn1Util.toBitString(signature));
  }

  public POPOSigningKeyInput getPoposkInput() {
    return poposkInput;
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algorithmIdentifier;
  }

  public Asn1BitString getSignature() {
    return signature;
  }

  public byte[] signature() {
    return signature.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        poposkInput == null ? null : Asn1TaggedObject.newImplicit(0, poposkInput),
        algorithmIdentifier, signature);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (poposkInput != null) {
      poposkInput.toStringWithLineSep(buf, indentLevel, "poposkInput", true);
    }

    algorithmIdentifier.toStringWithLineSep(buf, indentLevel, "algorithmIdentifier", true);
    signature.toStringWithLineSep(buf, indentLevel, "signature", true);

    return deleteLastNewLine(buf);
  }
}
