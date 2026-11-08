// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * Trait ::= SEQUENCE {
 *     traitId        TRAIT.&id({TraitSet}), -- Specifies the traitValue encoding
 *     traitCategory  OBJECT IDENTIFIER, -- Identifies the information category
 *                                       -- contained in traitValue
 *     traitRegistry  OBJECT IDENTIFIER, -- Identifies the registry used to match
 *                                       -- against the traitValue
 *     description    [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     descriptionURI [1] IMPLICIT IA5String  (SIZE (1..URIMAX)) OPTIONAL,
 *     traitValue     OCTET STRING
 *                ( CONTAINING TRAIT.&TraitValueType({TraitSet}{@traitId}) ENCODED BY der) }
 * }
 *
 * TRAIT ::= CLASS {
 *     &id OBJECT IDENTIFIER UNIQUE,
 *     &TraitValueType }
 * WITH SYNTAX {
 *     SYNTAX &TraitValueType
 *     IDENTIFIED BY &id }
 *
 * TraitSet TRAIT ::= {...}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Trait extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<Trait> {

    public Seq1(Trait... entries) {
      super(entries);
    }

    public Seq1(List<Trait> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected Trait newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Trait.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid traitId;

  private final Asn1Oid traitCategory;

  private final Asn1Oid traitRegistry;

  private final Asn1Utf8String description;

  private final Asn1IA5String descriptionURI;

  private final Asn1OctetString traitValue;

  private boolean parsed;

  private Asn1Boolean idBoolean;

  private CertificateIdentifier idCertificateIdentifier;

  private CommonCriteriaEvaluation idCommonCriteria;

  private Asn1OctetString idComponentClass;

  private ComponentIdentifierV11 idComponentIdentifierV11;

  private FIPSLevel idFIPSLevel;

  private ISO9000Certification idISO9000Level;

  private ComponentAddress idNetworkMAC;

  private Asn1Oid idOID;

  private Asn1Oid idPEN;

  private PlatformFirmwareCapabilities idPlatformFirmwareCapabilities;

  private PlatformFirmwareSignatureVerification idPlatformFirmwareSignatureVerification;

  private PlatformFirmwareUpdateCompliance idPlatformFirmwareUpdateCompliance;

  private PlatformHardwareCapabilities idPlatformHardwareCapabilities;

  private RTMTypes idRTM;

  private AttributeStatus idStatus;

  private URIReference idURI;

  private Asn1Utf8String idUTF8String;

  private Asn1IA5String idIA5String;

  private Asn1Utf8String idPEMCertString;

  private SubjectPublicKeyInfo idPublicKey;

  private Trait(Asn1Oid traitId, Asn1Oid traitCategory, Asn1Oid traitRegistry,
                Asn1Utf8String description, Asn1IA5String descriptionURI,
                Asn1OctetString traitValue) {
    this.traitId = Args.notNull(traitId, "traitId");
    this.traitCategory = Args.notNull(traitCategory, "traitCategory");
    this.traitRegistry = Args.notNull(traitRegistry, "traitRegistry");
    this.description = description;
    if (description != null) {
      Args.lengthRange(description, "description", 1, TcgConstants.STRMAX);
    }

    this.descriptionURI = descriptionURI;
    if (descriptionURI != null) {
      Args.lengthRange(descriptionURI, "descriptionURI", 1, TcgConstants.STRMAX);
    }

    this.traitValue = Args.notEmpty(traitValue, "traitValue");
  }

  public static Trait createNoParse(
      Asn1Oid traitId, Asn1Oid traitCategory, Asn1Oid traitRegistry,
      String description, String descriptionURI, Asn1Encodable traitValue) {
    return new Trait(traitId, traitCategory, traitRegistry, Asn1Util.toUtf8String(description),
        Asn1Util.toIA5String(descriptionURI),
        new Asn1OctetString(Args.notNull(traitValue, "traitValue").getEncoded()));
  }

  public static Trait create(
      Asn1Oid traitId, Asn1Oid traitCategory, Asn1Oid traitRegistry,
      String description, String descriptionURI, Asn1Encodable traitValue)
      throws CodecException {
    Trait r = createNoParse(traitId, traitCategory, traitRegistry, description,
        descriptionURI, traitValue);
    r.parseValue();
    return r;
  }

  private static Trait create2(
      Asn1Oid traitId, Asn1Oid traitCategory, Asn1Oid traitRegistry,
      String description, String descriptionURI, Asn1Encodable traitValue) {
    Trait r = createNoParse(traitId, traitCategory, traitRegistry, description,
        descriptionURI, traitValue);
    r.parsed = true;
    return r;
  }

  public static Trait ofIdBoolean(
      boolean value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    return ofIdBoolean(Asn1Boolean.getInstance(value), traitCategory,
        traitRegistry, description, descriptionURI);
  }

  public static Trait ofIdBoolean(
      Asn1Boolean value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_Boolean,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idBoolean = value;
    return r;
  }

  public static Trait ofIdCertificateIdentifier(
      CertificateIdentifier value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_certificateIdentifier,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idCertificateIdentifier = value;
    return r;
  }

  public static Trait ofIdCommonCriteria(
      CommonCriteriaEvaluation value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_CommonCriteria,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idCommonCriteria = value;
    return r;
  }

  public static Trait ofIdComponentClass(
      byte[] value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    return ofIdComponentClass(Asn1Util.toOctetString(value), traitCategory,
        traitRegistry, description, descriptionURI);
  }

  public static Trait ofIdComponentClass(
      Asn1OctetString value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_componentClass,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idComponentClass = value;
    return r;
  }

  public static Trait ofIdComponentIdentifierV11(
      ComponentIdentifierV11 value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_componentIdentifierV11,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idComponentIdentifierV11 = value;
    return r;
  }

  public static Trait ofIdFIPSLevel(
      FIPSLevel value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_FIPSLevel,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idFIPSLevel = value;
    return r;
  }

  public static Trait ofIdISO9000Level(
      ISO9000Certification value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_ISO9000Level,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idISO9000Level = value;
    return r;
  }

  public static Trait ofIdNetworkMAC(
      ComponentAddress value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_networkMAC,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idNetworkMAC = value;
    return r;
  }

  public static Trait ofIdOID(
      Asn1Oid value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_OID,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idOID = value;
    return r;
  }

  public static Trait ofIdPEN(
      Asn1Oid value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_PEN,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPEN = value;
    return r;
  }

  public static Trait ofIdPlatformFirmwareCapabilities(
      PlatformFirmwareCapabilities value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_platformFirmwareCapabilities,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPlatformFirmwareCapabilities = value;
    return r;
  }

  public static Trait ofIdPlatformFirmwareSignatureVerification(
      PlatformFirmwareSignatureVerification value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_platformFirmwareSignatureVerification,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPlatformFirmwareSignatureVerification = value;
    return r;
  }

  public static Trait ofIdPlatformFirmwareUpdateCompliance(
      PlatformFirmwareUpdateCompliance value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_platformFirmwareUpdateCompliance,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPlatformFirmwareUpdateCompliance = value;
    return r;
  }

  public static Trait ofIdPlatformHardwareCapabilities(
      PlatformHardwareCapabilities value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_platformHardwareCapabilities,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPlatformHardwareCapabilities = value;
    return r;
  }

  public static Trait ofIdRTM(
      RTMTypes value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_RTM,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idRTM = value;
    return r;
  }

  public static Trait ofIdStatus(
      AttributeStatus value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_status,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idStatus = value;
    return r;
  }

  public static Trait ofIdURI(
      URIReference value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_URI,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idURI = value;
    return r;
  }

  public static Trait ofIdUTF8String(
      String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    return ofIdUTF8String(Asn1Util.toUtf8String(value), traitCategory,
        traitRegistry, description, descriptionURI);
  }

  public static Trait ofIdUTF8String(
      Asn1Utf8String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_UTF8String,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idUTF8String = value;
    return r;
  }

  public static Trait ofIdIA5String(
      String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    return ofIdIA5String(Asn1Util.toIA5String(value), traitCategory,
        traitRegistry, description, descriptionURI);
  }

  public static Trait ofIdIA5String(
      Asn1IA5String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_IA5String,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idIA5String = value;
    return r;
  }

  public static Trait ofIdPEMCertString(
      String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    return ofIdPEMCertString(Asn1Util.toUtf8String(value), traitCategory,
        traitRegistry, description, descriptionURI);
  }

  public static Trait ofIdPEMCertString(
      Asn1Utf8String value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_PEMCertString,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPEMCertString = value;
    return r;
  }

  public static Trait ofIdPublicKey(
      SubjectPublicKeyInfo value, Asn1Oid traitCategory,
      Asn1Oid traitRegistry, String description, String descriptionURI) {
    Args.notNull(value, "value");
    Trait r = create2(TcgOIDs.tcg_tr_ID_PublicKey,
              traitCategory, traitRegistry, description, descriptionURI, value);
    r.idPublicKey = value;
    return r;
  }

  public Asn1Oid getTraitId() {
    return traitId;
  }

  public Asn1Oid getTraitCategory() {
    return traitCategory;
  }

  public Asn1Oid getTraitRegistry() {
    return traitRegistry;
  }

  public Asn1Utf8String getDescription() {
    return description;
  }

  public String description() {
    return Asn1Util.fromAsn1(description);
  }

  public Asn1IA5String getDescriptionURI() {
    return descriptionURI;
  }

  public String descriptionURI() {
    return Asn1Util.fromAsn1(descriptionURI);
  }

  public Asn1OctetString getTraitValue() {
    return traitValue;
  }

  public byte[] traitValue() {
    return traitValue.getOctets();
  }

  public Asn1Boolean getIdBoolean() {
    return idBoolean;
  }

  public Boolean idBoolean() {
    return Asn1Util.fromAsn1(idBoolean);
  }

  public CertificateIdentifier getIdCertificateIdentifier() {
    return idCertificateIdentifier;
  }

  public CommonCriteriaEvaluation getIdCommonCriteria() {
    return idCommonCriteria;
  }

  public Asn1OctetString getIdComponentClass() {
    return idComponentClass;
  }

  public byte[] idComponentClass() {
    return Asn1Util.fromAsn1(idComponentClass);
  }

  public ComponentIdentifierV11 getIdComponentIdentifierV11() {
    return idComponentIdentifierV11;
  }

  public FIPSLevel getIdFIPSLevel() {
    return idFIPSLevel;
  }

  public ISO9000Certification getIdISO9000Level() {
    return idISO9000Level;
  }

  public ComponentAddress getIdNetworkMAC() {
    return idNetworkMAC;
  }

  public Asn1Oid getIdOID() {
    return idOID;
  }

  public Asn1Oid getIdPEN() {
    return idPEN;
  }

  public PlatformFirmwareCapabilities getIdPlatformFirmwareCapabilities() {
    return idPlatformFirmwareCapabilities;
  }

  public PlatformFirmwareSignatureVerification getIdPlatformFirmwareSignatureVerification() {
    return idPlatformFirmwareSignatureVerification;
  }

  public PlatformFirmwareUpdateCompliance getIdPlatformFirmwareUpdateCompliance() {
    return idPlatformFirmwareUpdateCompliance;
  }

  public PlatformHardwareCapabilities getIdPlatformHardwareCapabilities() {
    return idPlatformHardwareCapabilities;
  }

  public RTMTypes getIdRTM() {
    return idRTM;
  }

  public AttributeStatus getIdStatus() {
    return idStatus;
  }

  public URIReference getIdURI() {
    return idURI;
  }

  public Asn1Utf8String getIdUTF8String() {
    return idUTF8String;
  }

  public String idUTF8String() {
    return Asn1Util.fromAsn1(idUTF8String);
  }

  public Asn1IA5String getIdIA5String() {
    return idIA5String;
  }

  public String idIA5String() {
    return Asn1Util.fromAsn1(idIA5String);
  }

  public Asn1Utf8String getIdPEMCertString() {
    return idPEMCertString;
  }

  public String idPEMCertString() {
    return Asn1Util.fromAsn1(idPEMCertString);
  }

  public SubjectPublicKeyInfo getIdPublicKey() {
    return idPublicKey;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(traitId, traitCategory, traitRegistry,
        (description == null) ? null : Asn1TaggedObject.newImplicit(0, description),
        (descriptionURI == null) ? null : Asn1TaggedObject.newImplicit(1, descriptionURI),
        traitValue);
  }

  public static Trait fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static Trait fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 4, 6);

    Asn1Oid traitId = seq.getOidAt(0);
    Asn1Oid traitCategory = seq.getOidAt(1);
    Asn1Oid traitRegistry = seq.getOidAt(2);

    int index = 3;
    Asn1Utf8String description = seq.isNotTaggedAt(index, 0) ? null
        : seq.getUtf8StringTaggedAt(index++, false);

    Asn1IA5String descriptionURI = seq.isNotTaggedAt(index, 1) ? null
        : seq.getIA5StringTaggedAt(index++, false);

    Asn1Util.checkSequenceEnd(index, size - 1);

    Asn1OctetString traitValue = seq.getOctetStringAt(index);
    return new Trait(traitId, traitCategory, traitRegistry,
        description, descriptionURI, traitValue);
  }

  private void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    byte[] octets = traitValue.getOctets();

    String id = traitId.getId();
    if (id.equals(TcgOIDs.tcg_tr_ID_Boolean.getId())) {
      idBoolean = Asn1Boolean.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_certificateIdentifier)) {
      idCertificateIdentifier = CertificateIdentifier.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_CommonCriteria)) {
      idCommonCriteria = CommonCriteriaEvaluation.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_componentClass)) {
      Asn1OctetString p = Asn1OctetString.fromEncoded(octets);
      int len = p.getOctetsLength();
      if (len != 4) {
        throw new IllegalArgumentException("length of traitValue (OCTET STRING) != 4");
      }
      idComponentClass = p;
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_componentIdentifierV11)) {
      idComponentIdentifierV11 = ComponentIdentifierV11.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_FIPSLevel)) {
      idFIPSLevel = FIPSLevel.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_ISO9000Level)) {
      idISO9000Level = ISO9000Certification.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_networkMAC)) {
      idNetworkMAC = ComponentAddress.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_OID)) {
      idOID = Asn1Oid.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_PEN)) {
      Asn1Oid p = Asn1Oid.fromEncoded(octets);
      if (!p.getId().startsWith("1.3.6.1.4.1.")) {
        throw new IllegalArgumentException(id + " is not a PEN OID");
      }
      idPEN = p;
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_platformFirmwareCapabilities)) {
      idPlatformFirmwareCapabilities = PlatformFirmwareCapabilities.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_platformFirmwareSignatureVerification)) {
      idPlatformFirmwareSignatureVerification =
          PlatformFirmwareSignatureVerification.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_platformFirmwareUpdateCompliance)) {
      idPlatformFirmwareUpdateCompliance = PlatformFirmwareUpdateCompliance.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_platformHardwareCapabilities)) {
      idPlatformHardwareCapabilities = PlatformHardwareCapabilities.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_RTM)) {
      idRTM = RTMTypes.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_status)) {
      idStatus = AttributeStatus.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_URI)) {
      idURI = URIReference.fromEncoded(octets);
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_UTF8String)) {
      Asn1Utf8String p = Asn1Utf8String.fromEncoded(octets);
      int len = p.getStringLength();
      if (len == 0) {
        throw new IllegalArgumentException("string length not in [1..MAX]");
      }
      idUTF8String = p;
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_IA5String)) {
      Asn1IA5String p = Asn1IA5String.fromEncoded(octets);
      int len = p.getStringLength();
      if (len == 0) {
        throw new IllegalArgumentException("string length not in [1..MAX]");
      }
      idIA5String = p;
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_PEMCertString)) {
      Asn1Utf8String p = Asn1Utf8String.fromEncoded(octets);
      int len = p.getStringLength();

      if (len == 0 || len > TcgConstants.CERTSTRMAX) {
        throw new IllegalArgumentException(
            "string length not in [1.." + TcgConstants.CERTSTRMAX + "]");
      }
      idPEMCertString = p;
    } else if (traitId.equals(TcgOIDs.tcg_tr_ID_PublicKey)) {
      idPublicKey = SubjectPublicKeyInfo.fromEncoded(octets);
    }

    parsed = true;
  }

  private Asn1Encodable parsedValue() {
    if (!parsed) {
      return traitValue;
    } else if (idBoolean != null) {
      return idBoolean;
    } else if (idCertificateIdentifier != null) {
      return idCertificateIdentifier;
    } else if (idCommonCriteria != null) {
      return idCommonCriteria;
    } else if (idComponentClass != null) {
      return idComponentClass;
    } else if (idComponentIdentifierV11 != null) {
      return idComponentIdentifierV11;
    } else if (idFIPSLevel != null) {
      return idFIPSLevel;
    } else if (idISO9000Level != null) {
      return idISO9000Level;
    } else if (idNetworkMAC != null) {
      return idNetworkMAC;
    } else if (idOID != null) {
      return idOID;
    } else if (idPEN != null) {
      return idPEN;
    } else if (idPlatformFirmwareCapabilities != null) {
      return idPlatformFirmwareCapabilities;
    } else if (idPlatformFirmwareSignatureVerification != null) {
      return idPlatformFirmwareSignatureVerification;
    } else if (idPlatformFirmwareUpdateCompliance != null) {
      return idPlatformFirmwareUpdateCompliance;
    } else if (idPlatformHardwareCapabilities != null) {
      return idPlatformHardwareCapabilities;
    } else if (idRTM != null) {
      return idRTM;
    } else if (idStatus != null) {
      return idStatus;
    } else if (idURI != null) {
      return idURI;
    } else if (idUTF8String != null) {
      return idUTF8String;
    } else if (idIA5String != null) {
      return idIA5String;
    } else if (idPEMCertString != null) {
      return idPEMCertString;
    } else if (idPublicKey != null) {
      return idPublicKey;
    } else {
      return traitValue;
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    traitCategory.toStringNoLineSep(buf, indentLevel, "traitCategory", true);
    traitRegistry.toStringNoLineSep(buf, indentLevel, "traitRegistry", true);
    if (description != null) {
      description.toStringNoLineSep(buf, indentLevel, "description", true);
    }

    if (descriptionURI != null) {
      descriptionURI.toStringNoLineSep(buf, indentLevel, "descriptionURI", true);
    }

    return parsedValue().toStringWithLineSep(buf, indentLevel, "traitValue");
  }

}
