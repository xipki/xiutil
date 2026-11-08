// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * ProofOfPossession ::= CHOICE {
 *     raVerified        [0] NULL,
 *                       -- used if the RA has already verified that the
 *                       -- requester is in possession of the private key
 *     signature         [1] POPOSigningKey,
 *     keyEncipherment   [2] POPOPrivKey,
 *     keyAgreement      [3] POPOPrivKey }
 *
 * POPOSigningKey ::= SEQUENCE { .. }
 * POPOPrivKey ::= CHOICE { ... }
 * </pre>
 * @return a basic ASN.1 object representation.
 *
 * @author Lijun Liao (xipki)
 */
public class ProofOfPossession extends Asn1Encodable {

  public static final int tag_raVerified = 0;
  public static final int tag_signature = 1;
  public static final int tag_keyEncipherment = 2;
  public static final int tag_keyAgreement = 3;

  private final int tagNo;
  private final Asn1Null raVerified;
  private final POPOSigningKey signature;
  private final POPOPrivKey keyEncipherment;
  private final POPOPrivKey keyAgreement;

  private ProofOfPossession(Asn1Null raVerified, POPOSigningKey signature,
                           POPOPrivKey keyEncipherment, POPOPrivKey keyAgreement) {
    this.raVerified = raVerified;
    this.signature = signature;
    this.keyEncipherment = keyEncipherment;
    this.keyAgreement = keyAgreement;
    if (raVerified != null) {
      tagNo = tag_raVerified;
    } else if (signature != null) {
      tagNo = tag_signature;
    } else if (keyEncipherment != null) {
      tagNo = tag_keyEncipherment;
    } else {
      tagNo = tag_keyAgreement;
    }
  }

  public static ProofOfPossession ofRaVerified() {
    return new ProofOfPossession(Asn1Null.INSTANCE, null, null, null);
  }

  public static ProofOfPossession ofSignature(POPOSigningKey signature) {
    return new ProofOfPossession(null, Args.notNull(signature, "signature"), null, null);
  }

  public static ProofOfPossession ofKeyEncipherment(POPOPrivKey keyEncipherment) {
    return new ProofOfPossession(null, null,
        Args.notNull(keyEncipherment, "keyEncipherment"), null);
  }

  public static ProofOfPossession ofKeyAgreement(POPOPrivKey keyAgreement) {
    return new ProofOfPossession(null, null, null, Args.notNull(keyAgreement, "keyAgreement"));
  }

  public static ProofOfPossession fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    int tagNo = asn1.getTagNo();

    if (tagNo == 0) {
      return ofRaVerified();
    } else if (tagNo == 1) { // IMPLICIT
      return ofSignature(POPOSigningKey.fromAsn1(asn1.getImplicitSequenceBase()));
    } else if (tagNo == 2) { // CHOICE so explicit
      return ofKeyEncipherment(POPOPrivKey.fromAsn1(asn1.getExplicitTaggedBase()));
    } else if (tagNo == 3) { // CHOICE so explicit
      return ofKeyAgreement(POPOPrivKey.fromAsn1(asn1.getExplicitTaggedBase()));
    } else {
      throw new IllegalArgumentException("unknown tag in ProofOfPossession " + tagNo);
    }
  }

  public int getTagNo() {
    return tagNo;
  }

  public Asn1Null getRaVerified() {
    return raVerified;
  }

  public POPOSigningKey getSignature() {
    return signature;
  }

  public POPOPrivKey getKeyEncipherment() {
    return keyEncipherment;
  }

  public POPOPrivKey getKeyAgreement() {
    return keyAgreement;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return raVerified != null ? Asn1TaggedObject.newImplicit(0, raVerified)
        : signature   != null ? Asn1TaggedObject.newImplicit(1, signature)
        // CHOICE -> EXPLICIT
        : keyEncipherment != null ? Asn1TaggedObject.newExplicit(2, keyEncipherment)
        // CHOICE -> EXPLICIT
        : Asn1TaggedObject.newExplicit(3, keyAgreement);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (raVerified != null) {
      return raVerified.toStringNoLineSep(buf, indentLevel, "raVerified");
    }

    if (signature != null) {
      return signature.toStringWithLineSep(buf, indentLevel, "signature");
    }

    if (keyEncipherment != null) {
      return keyEncipherment.toStringWithLineSep(buf, indentLevel, "keyEncipherment");
    }

    return keyAgreement.toStringWithLineSep(buf, indentLevel, "keyAgreement");
  }

}
