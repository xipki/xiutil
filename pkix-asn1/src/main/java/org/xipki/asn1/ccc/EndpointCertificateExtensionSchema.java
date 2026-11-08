// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.asn1.ccc;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * CCC InstanceCACertificateExtensionSchema.
 *
 * Note it is not specified whether the tags [0] and [1] is IMPLICIT or
 * EXPLICIT. We assume in this class the "EXPLICIT" which is also
 * for the "extensions" in the TBSCertificate.
 *
 * <pre>
 * EndpointCertificateExtensionSchema ::= SEQUENCE {
 *     extension_version    INTEGER (1..255),
 *     vehicle_identifier   OCTET STRING (SIZE (8)),
 *     option_group_1       OCTET STRING (SIZE (1)),
 *     option_group_2       OCTET STRING (SIZE (1)),
 *     protocol_version     OCTET STRING (SIZE (2)),
 *     vehicle_PK           PublicKey,
 *     initial_key_slot     OCTET STRING (SIZE (1..8)),
 *     authorized_PK_list   SEQUENCE (SIZE (1..5)) OF PublicKey OPTIONAL,
 *     confidential_mailbox_size [0] INTEGER (1..65535) OPTIONAL,
 *     private_mailbox_size      [1] INTEGER (1..65535) OPTIONAL,
 *     account_info_hash         OCTET STRING (SIZE (32)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EndpointCertificateExtensionSchema extends Asn1Encodable {

  private final Asn1Integer extensionVersion;

  private final Asn1OctetString vehicleIdentifier;

  private final Asn1OctetString optionGroup1;

  private final Asn1OctetString optionGroup2;

  private final Asn1OctetString protocolVersion;

  private final SubjectPublicKeyInfo vehiclePK;

  private final Asn1OctetString initialKeySlot;

  private final SubjectPublicKeyInfo.Seq1 authorizedPKList;

  private final Asn1Integer confidentialMailboxSize;

  private final Asn1Integer privateMailboxSize;

  private final Asn1OctetString accountInfoHash;

  public EndpointCertificateExtensionSchema(
      int extensionVersion, byte[] vehicleIdentifier, byte optionGroup1, byte optionGroup2,
      byte[] protocolVersion, SubjectPublicKeyInfo vehiclePK, byte[] initialKeySlot) {
    this(extensionVersion, vehicleIdentifier, optionGroup1, optionGroup2,
        protocolVersion, vehiclePK, initialKeySlot,
        null, null, null, null);
  }

  public EndpointCertificateExtensionSchema(
      int extensionVersion, byte[] vehicleIdentifier, byte optionGroup1, byte optionGroup2,
      byte[] protocolVersion, SubjectPublicKeyInfo vehiclePK, byte[] initialKeySlot,
      List<SubjectPublicKeyInfo> authorizedPKList,
      Integer confidentialMailboxSize, Integer privateMailboxSize, byte[] accountInfoHash) {
    Args.range(extensionVersion, "extensionVersion", 1, 255);
    this.extensionVersion = new Asn1Integer(BigInteger.valueOf(extensionVersion));
    this.vehicleIdentifier = new Asn1OctetString(
        Args.fixedLen(vehicleIdentifier, "vehicleIdentifier", 8));
    this.optionGroup1 = new Asn1OctetString(new byte[]{optionGroup1});
    this.optionGroup2 = new Asn1OctetString(new byte[]{optionGroup2});
    this.protocolVersion = new Asn1OctetString(
        Args.fixedLen(protocolVersion, "protocolVersion", 2));
    this.vehiclePK = Args.notNull(vehiclePK, "vehiclePK");
    this.initialKeySlot = new Asn1OctetString(
        Args.variableLen(initialKeySlot, "initialKeySlot", 1, 8));

    if (authorizedPKList == null || authorizedPKList.isEmpty()) {
      this.authorizedPKList = null;
    } else {
      this.authorizedPKList = new SubjectPublicKeyInfo.Seq1(
          authorizedPKList.toArray(new SubjectPublicKeyInfo[0]));
    }

    if (confidentialMailboxSize == null) {
      this.confidentialMailboxSize = null;
    } else {
      this.confidentialMailboxSize = new Asn1Integer(BigInteger.valueOf(
          Args.range(confidentialMailboxSize, "confidentialMailboxSize", 1, 65535)));
    }

    if (privateMailboxSize == null) {
      this.privateMailboxSize = null;
    } else {
      this.privateMailboxSize = new Asn1Integer(BigInteger.valueOf(
          Args.range(privateMailboxSize, "privateMailboxSize", 1, 65535)));
    }

    if (accountInfoHash == null) {
      this.accountInfoHash = null;
    } else {
      this.accountInfoHash = new Asn1OctetString(
          Args.fixedLen(accountInfoHash, "accountInfoHash", 32));
    }
  }

  private EndpointCertificateExtensionSchema(
      Asn1Integer extensionVersion, Asn1OctetString vehicleIdentifier,
      Asn1OctetString optionGroup1, Asn1OctetString optionGroup2,
      Asn1OctetString protocolVersion, SubjectPublicKeyInfo vehiclePK,
      Asn1OctetString initialKeySlot, SubjectPublicKeyInfo.Seq1 authorizedPKList,
      Asn1Integer confidentialMailboxSize, Asn1Integer privateMailboxSize,
      Asn1OctetString accountInfoHash) {
    this.extensionVersion = extensionVersion;
    this.vehicleIdentifier = vehicleIdentifier;
    this.optionGroup1 = optionGroup1;
    this.optionGroup2 = optionGroup2;
    this.protocolVersion = protocolVersion;
    this.vehiclePK = vehiclePK;
    this.initialKeySlot = initialKeySlot;
    this.authorizedPKList = authorizedPKList;
    this.confidentialMailboxSize = confidentialMailboxSize;
    this.privateMailboxSize = privateMailboxSize;
    this.accountInfoHash = accountInfoHash;
  }

  public Asn1Integer getExtensionVersion() {
    return extensionVersion;
  }

  public Asn1OctetString getVehicleIdentifier() {
    return vehicleIdentifier;
  }

  public Asn1OctetString getOptionGroup1() {
    return optionGroup1;
  }

  public Asn1OctetString getOptionGroup2() {
    return optionGroup2;
  }

  public Asn1OctetString getProtocolVersion() {
    return protocolVersion;
  }

  public SubjectPublicKeyInfo getVehiclePK() {
    return vehiclePK;
  }

  public Asn1OctetString getInitialKeySlot() {
    return initialKeySlot;
  }

  public SubjectPublicKeyInfo.Seq1 getAuthorizedPKList() {
    return authorizedPKList;
  }

  public Asn1Integer getConfidentialMailboxSize() {
    return confidentialMailboxSize;
  }

  public Asn1Integer getPrivateMailboxSize() {
    return privateMailboxSize;
  }

  public Asn1OctetString getAccountInfoHash() {
    return accountInfoHash;
  }

  public int extensionVersion() {
    return extensionVersion.intValueExact();
  }

  public byte[] vehicleIdentifier() {
    return vehicleIdentifier.getOctets();
  }

  public byte[] optionGroup1() {
    return optionGroup1.getOctets();
  }

  public byte[] optionGroup2() {
    return optionGroup2.getOctets();
  }

  public byte[] protocolVersion() {
    return protocolVersion.getOctets();
  }

  public byte[] initialKeySlot() {
    return initialKeySlot.getOctets();
  }

  public Integer confidentialMailboxSize() {
    return Asn1Util.fromAsn1Int(confidentialMailboxSize);
  }

  public Integer privateMailboxSize() {
    return Asn1Util.fromAsn1Int(privateMailboxSize);
  }

  public byte[] accountInfoHash() {
    return Asn1Util.fromAsn1(accountInfoHash);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(extensionVersion, vehicleIdentifier,
        optionGroup1, optionGroup2, protocolVersion, vehiclePK, initialKeySlot, authorizedPKList,
        (confidentialMailboxSize == null) ? null
            : Asn1TaggedObject.newExplicit(0, confidentialMailboxSize),
        (privateMailboxSize == null) ? null
            : Asn1TaggedObject.newExplicit(1, privateMailboxSize),
        accountInfoHash);
  }

  public static EndpointCertificateExtensionSchema fromEncoded(byte[] encoded)
      throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static EndpointCertificateExtensionSchema fromAsn1(Asn1Sequence seq)
      throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 7, 11);

    Asn1Integer extensionVersion = seq.getNonNegativeIntegerAt(0);
    Asn1OctetString vehicleIdentifier = seq.getOctetStringAt(1);
    Asn1OctetString optionGroup1 = seq.getOctetStringAt(2);
    Args.fixedLen(optionGroup1, "optionGroup1", 1);

    Asn1OctetString optionGroup2 = seq.getOctetStringAt(3);
    Args.fixedLen(optionGroup2, "optionGroup2", 1);

    Asn1OctetString protocolVersion = seq.getOctetStringAt(4);
    SubjectPublicKeyInfo vehiclePK = SubjectPublicKeyInfo.fromAsn1(seq.getSequenceAt(5));
    Asn1OctetString initialKeySlot = seq.getOctetStringAt(6);

    int index = 7;
    SubjectPublicKeyInfo.Seq1 authorizedPKList = seq.notHasSequence(index) ? null
        : SubjectPublicKeyInfo.Seq1.fromAsn1(seq.getSequenceAt(index++));
    if (authorizedPKList != null) {
      if (authorizedPKList.size() > 5) {
        throw new CodecException("invalid authorized_PKList size: " + authorizedPKList.size());
      }
    }

    Asn1Integer confidentialMailboxSize = seq.isNotTaggedAt(index, 0) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, true);

    Asn1Integer privateMailboxSize = seq.isNotTaggedAt(index, 1) ? null
        : seq.getNonNegativeIntegerTaggedAt(index++, true);

    Asn1OctetString accountInfoHash = seq.notHasOctetString(index) ? null
        : seq.getOctetStringAt(index++);

    Asn1Util.checkSequenceEnd(index, size);

    return new EndpointCertificateExtensionSchema(extensionVersion, vehicleIdentifier,
        optionGroup1, optionGroup2, protocolVersion, vehiclePK, initialKeySlot,
        authorizedPKList, confidentialMailboxSize, privateMailboxSize, accountInfoHash);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    extensionVersion.toStringNoLineSep(buf, indentLevel, "extension_version", true);
    vehicleIdentifier.toStringNoLineSep(buf, indentLevel, "vehicle_identifier", true);
    optionGroup1.toStringNoLineSep(buf, indentLevel, "option_group_1", true);
    optionGroup2.toStringNoLineSep(buf, indentLevel, "option_group_2", true);
    protocolVersion.toStringNoLineSep(buf, indentLevel, "protocol_version", true);
    vehiclePK.toStringWithLineSep(buf, indentLevel, "vehicle_PK", true);
    initialKeySlot.toStringNoLineSep(buf, indentLevel, "initial_key_slot", true);
    if (authorizedPKList != null) {
      authorizedPKList.toStringWithLineSep(buf, indentLevel, "authorized_PK_list", true);
    }

    if (confidentialMailboxSize != null) {
      confidentialMailboxSize.toStringNoLineSep(buf, indentLevel,
          "confidential_mailbox_size", true);
    }

    if (privateMailboxSize != null) {
      privateMailboxSize.toStringNoLineSep(buf, indentLevel, "private_mailbox_size", true);
    }

    if (accountInfoHash != null) {
      accountInfoHash.toStringNoLineSep(buf, indentLevel, "account_info_hash", true);
    }

    return deleteLastNewLine(buf);
  }

}
