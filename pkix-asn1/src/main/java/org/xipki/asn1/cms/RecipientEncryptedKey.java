// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * RecipientEncryptedKey ::= SEQUENCE {
 *     rid KeyAgreeRecipientIdentifier,
 *     encryptedKey EncryptedKey
 * }
 *
 * EncryptedKey ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RecipientEncryptedKey extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<RecipientEncryptedKey> {

    public Seq0(RecipientEncryptedKey... entries) {
      super(entries);
    }

    public Seq0(List<RecipientEncryptedKey> entries) {
      super(entries);
    }

    private Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected RecipientEncryptedKey newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return RecipientEncryptedKey.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final KeyAgreeRecipientIdentifier identifier;
  private final Asn1OctetString encryptedKey;

  public static RecipientEncryptedKey fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    KeyAgreeRecipientIdentifier identifier =
        KeyAgreeRecipientIdentifier.fromAsn1(seq.getObjectAt(0));
    Asn1OctetString encryptedKey = seq.getOctetStringAt(1);
    return new RecipientEncryptedKey(identifier, encryptedKey);
  }

  public RecipientEncryptedKey(KeyAgreeRecipientIdentifier id, byte[] encryptedKey) {
    this(id, Asn1Util.toOctetString(encryptedKey));
  }

  public RecipientEncryptedKey(KeyAgreeRecipientIdentifier id, Asn1OctetString encryptedKey) {
    this.identifier = Args.notNull(id, "id");
    this.encryptedKey = Args.notNull(encryptedKey, "encryptedKey");
  }

  public KeyAgreeRecipientIdentifier getIdentifier() {
    return identifier;
  }

  public Asn1OctetString getEncryptedKey() {
    return encryptedKey;
  }

  public byte[] encryptedKey() {
    return encryptedKey.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(identifier, encryptedKey);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    identifier.toStringWithLineSep(buf, indentLevel, "identifier", true);
    encryptedKey.toStringWithLineSep(buf, indentLevel, "encryptedKey", true);

    return deleteLastNewLine(buf);
  }

}
