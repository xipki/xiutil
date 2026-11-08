// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * PKIArchiveOptions ::= CHOICE {
 *   encryptedPrivKey     [0] EncryptedKey,
 *      -- the actual value of the private key
 *   keyGenParameters     [1] KeyGenParameters,
 *      -- parameters which allow the private key to be re-generated
 *   archiveRemGenPrivKey [2] BOOLEAN }
 *      -- set to TRUE if sender wishes receiver to archive the private
 *      -- key of a key pair that the receiver generates in response to
 *      -- this request; set to FALSE if no archival is desired.
 *
 * KeyGenParameters ::= OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKIArchiveOptions extends Asn1Encodable {

  public static final int tag_encryptedPrivKey = 0;

  public static final int tag_keyGenParameters = 1;

  public static final int tag_archiveRemGenPrivKey = 2;

  private final int tagNo;

  private final EncryptedKey encryptedPrivKey;

  private final Asn1OctetString keyGenParameters;

  private final Asn1Boolean archiveRemGenPrivKey;

  public static PKIArchiveOptions fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    int tagNo = Args.notNull(asn1, "asn1").getTagNo();

    if (tagNo == 0) {
      // CHOICE -> EXPLICIT
      return ofEncryptedKey(EncryptedKey.fromAsn1(asn1.getExplicitBase()));
    } else if (tagNo == 1) {
      return ofKeyGenParameters(asn1.getImplicitOctetStringBase());
    } else if (tagNo == 2) {
      return ofArchiveRemGenPrivKey(asn1.getImplicitBooleanBase().isTrue());
    } else {
      throw new IllegalArgumentException("unknown tag number: " + tagNo);
    }
  }

  private PKIArchiveOptions(
      EncryptedKey encryptedPrivKey, Asn1OctetString keyGenParameters,
      Asn1Boolean archiveRemGenPrivKey) {
    this.encryptedPrivKey = encryptedPrivKey;
    this.keyGenParameters = keyGenParameters;
    this.archiveRemGenPrivKey = archiveRemGenPrivKey;
    if (encryptedPrivKey != null) {
      this.tagNo = tag_encryptedPrivKey;
    } else if (keyGenParameters != null) {
      this.tagNo = tag_keyGenParameters;
    } else {
      this.tagNo = tag_encryptedPrivKey;
    }
  }

  public static PKIArchiveOptions ofEncryptedKey(EncryptedKey encKey) {
    return new PKIArchiveOptions(Args.notNull(encKey, "encKey"),
        null, null);
  }

  public static PKIArchiveOptions ofKeyGenParameters(Asn1OctetString keyGenParameters) {
    return new PKIArchiveOptions(null,
        Args.notNull(keyGenParameters, "keyGenParameters"), null);
  }

  public static PKIArchiveOptions ofArchiveRemGenPrivKey(boolean archiveRemGenPrivKey) {
    return new PKIArchiveOptions(null, null,
        Asn1Boolean.getInstance(archiveRemGenPrivKey));
  }

  public int getTagNo() {
    return tagNo;
  }

  public EncryptedKey getEncryptedPrivKey() {
    return encryptedPrivKey;
  }

  public Asn1OctetString getKeyGenParameters() {
    return keyGenParameters;
  }

  public Asn1Boolean getArchiveRemGenPrivKey() {
    return archiveRemGenPrivKey;
  }

  public byte[] keyGenParameters() {
    return Asn1Util.fromAsn1(keyGenParameters);
  }

  public Boolean archiveRemGenPrivKey() {
    return Asn1Util.fromAsn1(archiveRemGenPrivKey);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    if (encryptedPrivKey != null) {
      return Asn1TaggedObject.newImplicit(0, encryptedPrivKey);
    } else if (keyGenParameters != null) {
      return Asn1TaggedObject.newImplicit(1, keyGenParameters);
    } else {
      return Asn1TaggedObject.newImplicit(2, archiveRemGenPrivKey);
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (encryptedPrivKey != null) {
      return encryptedPrivKey.toStringWithLineSep(buf, indentLevel, "encryptedPrivKey");
    }

    if (keyGenParameters != null) {
      return keyGenParameters.toStringWithLineSep(buf, indentLevel, "keyGenParameters");
    }

    return archiveRemGenPrivKey.toStringNoLineSep(buf, indentLevel, "archiveRemGenPrivKey");
  }

}
