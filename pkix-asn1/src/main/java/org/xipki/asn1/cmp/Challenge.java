// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 4210
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * Challenge ::= SEQUENCE {
 *     owf        AlgorithmIdentifier  OPTIONAL,
 *          -- MUST be present in the first Challenge; MAY be omitted in
 *          -- any subsequent Challenge in POPODecKeyChallContent (if
 *          -- omitted, then the owf used in the immediately preceding
 *          -- Challenge is to be used).
 *     witness    OCTET STRING,
 *          -- the result of applying the one-way function (owf) to a
 *          -- randomly-generated INTEGER, A.  [Note that a different
 *          -- INTEGER MUST be used for each Challenge.]
 *     challenge  OCTET STRING   -- deprecated
 *          -- the encryption (under the public key for which the cert.
 *          -- request is being made) of Rand
 *     encryptedRand [0] EnvelopedData OPTIONAL
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Challenge extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<Challenge> {

    public Seq0(Challenge... entries) {
      super(entries);
    }

    public Seq0(List<Challenge> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected Challenge newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Challenge.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final AlgorithmIdentifier owf;
  private final Asn1OctetString witness;
  private final Asn1OctetString challenge;
  private final EnvelopedData encryptedRand;

  public static Challenge fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    int index = 0;

    AlgorithmIdentifier owf = seq.notHasSequence(index) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));

    Asn1OctetString witness = seq.getOctetStringAt(index++);
    Asn1OctetString challenge = seq.getOctetStringAt(index++);

    EnvelopedData encryptedRand = seq.isNotTaggedAt(index, 0) ? null
        : EnvelopedData.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);
    if (encryptedRand != null && challenge.getOctetsLength() != 0) {
      throw new IllegalArgumentException("ambiguous challenge");
    }

    return new Challenge(owf, witness, challenge, encryptedRand);
  }

  private Challenge(AlgorithmIdentifier owf, Asn1OctetString witness, Asn1OctetString challenge,
                   EnvelopedData encryptedRand) {
    this.owf = owf;
    this.witness = Args.notNull(witness, "witness");
    this.challenge = Args.notNull(challenge, "challenge");
    this.encryptedRand = encryptedRand;
  }

  public Challenge(byte[] witness, EnvelopedData encryptedRand) {
    this(null, witness, encryptedRand);
  }

  public Challenge(AlgorithmIdentifier owf, byte[] witness, byte[] challenge) {
    this.owf = owf;
    this.witness = new Asn1OctetString(Args.notNull(witness, ""));
    this.challenge = new Asn1OctetString(Args.notNull(challenge, "challenge"));
    this.encryptedRand = null;
  }

  public Challenge(AlgorithmIdentifier owf, byte[] witness, EnvelopedData encryptedRand) {
    this.owf = owf;
    this.witness = new Asn1OctetString(Args.notNull(witness, ""));
    this.challenge = new Asn1OctetString(new byte[0]);
    this.encryptedRand = Args.notNull(encryptedRand, "encryptedRand");
  }

  public AlgorithmIdentifier getOwf() {
    return owf;
  }

  public Asn1OctetString getWitness() {
    return witness;
  }

  public Asn1OctetString getChallenge() {
    return challenge;
  }

  public EnvelopedData getEncryptedRand() {
    return encryptedRand;
  }

  public byte[] witness() {
    return witness.getOctets();
  }

  public byte[] challenge() {
    return challenge.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(owf, witness, challenge,
        encryptedRand == null ? null : Asn1TaggedObject.newExplicit(0, encryptedRand));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (owf != null) {
      owf.toStringWithLineSep(buf, indentLevel, "owf", true);
    }

    witness.toStringWithLineSep(buf, indentLevel, "witness", true);
    challenge.toStringWithLineSep(buf, indentLevel, "challenge", true);

    if (encryptedRand != null) {
      encryptedRand.toStringWithLineSep(buf, indentLevel, "encryptedRand", true);
    }

    return deleteLastNewLine(buf);
  }

}
