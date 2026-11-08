// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.x509.GeneralName;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * POPOSigningKeyInput ::= SEQUENCE {
 *     authInfo CHOICE {
 *         sender    [0] GeneralName,
 *                       -- used only if an authenticated identity has been
 *                       -- established for the sender (e.g., a DN from a
 *                       -- previously-issued and currently-valid certificate
 *         publicKeyMAC  PKMACValue },
 *                       -- used if no authenticated GeneralName currently exists for
 *                       -- the sender; publicKeyMAC contains a password-based MAC
 *                       -- on the DER-encoded value of publicKey
 *     publicKey SubjectPublicKeyInfo }  -- from CertTemplate
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class POPOSigningKeyInput extends Asn1Encodable {

  private final GeneralName sender;
  private final PKMACValue publicKeyMAC;
  private final SubjectPublicKeyInfo publicKey;

  public static POPOSigningKeyInput fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Primitive p = seq.getObjectAt(0);

    GeneralName sender = null;
    PKMACValue publicKeyMAC = null;
    if (p instanceof Asn1TaggedObject) {
      // sender [0] GeneralName
      sender = GeneralName.fromAsn1(seq.getTaggedAt(0, 0).getExplicitTaggedBase());
    } else {
      publicKeyMAC = PKMACValue.fromAsn1(p.asSequence());
    }

    SubjectPublicKeyInfo publicKey = SubjectPublicKeyInfo.fromAsn1(seq.getSequenceAt(1));
    return sender != null ? new POPOSigningKeyInput(sender, publicKey)
        : new POPOSigningKeyInput(publicKeyMAC, publicKey);
  }

  public POPOSigningKeyInput(GeneralName sender, SubjectPublicKeyInfo spki) {
    this.sender = Args.notNull(sender, "sender");
    this.publicKeyMAC = null;
    this.publicKey = Args.notNull(spki, "spki");
  }

  public POPOSigningKeyInput(PKMACValue pkmac, SubjectPublicKeyInfo spki) {
    this.sender = null;
    this.publicKeyMAC = Args.notNull(pkmac, "pkmac");
    this.publicKey = Args.notNull(spki, "spki");
  }

  public GeneralName getSender() {
    return sender;
  }

  public PKMACValue getPublicKeyMAC() {
    return publicKeyMAC;
  }

  public SubjectPublicKeyInfo getPublicKey() {
    return publicKey;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(
        sender != null ? Asn1TaggedObject.newExplicit(0, sender) : publicKeyMAC,
        publicKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (sender != null) {
      sender.toStringWithLineSep(buf, indentLevel, "sender", true);
    }

    if (publicKeyMAC != null) {
      publicKeyMAC.toStringWithLineSep(buf, indentLevel, "publicKeyMAC", true);
    }

    publicKey.toStringWithLineSep(buf, indentLevel, "publicKey", true);

    return deleteLastNewLine(buf);
  }
}
