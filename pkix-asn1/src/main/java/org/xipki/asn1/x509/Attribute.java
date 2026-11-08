// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.cms.CMSAlgorithmProtection;
import org.xipki.asn1.ess.ContentHints;
import org.xipki.asn1.est.ChangeSubjectName;
import org.xipki.asn1.tcg.PlatformConfigurationV3;
import org.xipki.asn1.tcg.TCGCredentialType;
import org.xipki.asn1.tcg.TCGPlatformSpecification;
import org.xipki.asn1.tcg.TCGSpecificationVersion;
import org.xipki.asn1.tcg.Traits;
import org.xipki.asn1.x500.DirectoryString;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.TcgOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <pre>
 * Attribute ::= SEQUENCE {
 *     attrType   OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue
 * }
 *
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Attribute extends Asn1Encodable {

  private static abstract class AttributeColl extends AbstractCollection<Attribute> {

    public AttributeColl(boolean isSet, int min, Attribute... entries) {
      super(isSet, min, Integer.MAX_VALUE, entries);
    }

    public AttributeColl(boolean isSet, int min, List<Attribute> entries) {
      super(isSet, min, Integer.MAX_VALUE, entries);
    }

    protected AttributeColl(boolean isSet, int min, AbstractAsn1Collection seq)
        throws CodecException {
      super(isSet, min, Integer.MAX_VALUE, seq);
    }

    @Override
    protected Attribute newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Attribute.fromAsn1(coll.getSequenceAt(index));
    }

    public boolean hasAttribute(Asn1Oid attrType) {
      for (Attribute m : entries) {
        if (attrType.equals(m.attrType)) {
          return true;
        }
      }

      return false;
    }

    public Attribute getOnlyAttribute(Asn1Oid attrType)
        throws CodecException {
      Attribute found = null;
      for (Attribute m : entries) {
        if (attrType.equals(m.attrType)) {
          if (found != null) {
            throw new CodecException("duplicated attribute " + attrType);
          }
          found = m;
        }
      }

      return found;
    }

    public Attribute getFirstAttribute(Asn1Oid attrType) {
      for (Attribute m : entries) {
        if (attrType.equals(m.attrType)) {
          return m;
        }
      }

      return null;
    }

    public List<Attribute> getAllAttributes(Asn1Oid attrType) {
      List<Attribute> found = new ArrayList<>(1);

      for (Attribute m : entries) {
        if (attrType.equals(m.attrType)) {
          found.add(m);
        }
      }

      return found;
    }

  }

  public static class Seq1 extends AttributeColl {

    public Seq1(Attribute... entries) {
      super(false, 1, entries);
    }

    public Seq1(List<Attribute> entries) {
      super(false, 1, entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(false, 1, seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

  }

  public static class Set1 extends AttributeColl {

    public Set1(Attribute... entries) {
      super(true, 1, entries);
    }

    public Set1(List<Attribute> entries) {
      super(true, 1, entries);
    }

    protected Set1(Asn1Set set) throws CodecException {
      super(true, 1, set);
    }

    public static Set1 fromAsn1(Asn1Set set) throws CodecException {
      return new Set1(set);
    }

  }

  public static class Set0 extends AttributeColl {

    public Set0(Attribute... entries) {
      super(true, 0, entries);
    }

    public Set0(List<Attribute> entries) {
      super(true, 0, entries);
    }

    protected Set0(Asn1Set set) throws CodecException {
      super(true, 0, set);
    }

    public static Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new Set0(set);
    }

  }

  private final Asn1Oid attrType;
  private final Asn1Set attrValues;

  private boolean parsed;

  // ----- X.520 -----
  /**
   * country code - PrintableString (SIZE(2)).
   */
  Asn1PrintableString country;

  /**
   * organization - StringType(SIZE(1..64)). DirectoryString.
   */
  private DirectoryString organization;

  /**
   * organizationIdentifier - StringType(SIZE(1..64)). DirectoryString
   */
  private DirectoryString organizationIdentifier;

  /**
   * organizational unit name - StringType(SIZE(1..64)). DirectoryString
   */
  private DirectoryString organizationalUnit;

  /**
   * Title. DirectoryString
   */
  private DirectoryString title;

  /**
   * common name - StringType(SIZE(1..64)), X520CommonName
   */
  private DirectoryString commonName;

  /**
   * device serial number name - PrintableString (SIZE(1..64))
   */
  private Asn1PrintableString serialNumber;

  /**
   * street - StringType(SIZE(1..64)). DirectoryString
   */
  private DirectoryString street;

  /**
   * locality name - StringType(SIZE(1..64)). DirectoryString.
   */
  private DirectoryString locality;

  /**
   * state, or province name - StringType(SIZE(1..64)). DirectoryString.
   */
  private DirectoryString state;

  /**
   * Naming attributes of type X520name.
   */
  private DirectoryString surname;

  /**
   * Naming attributes of type X520name.
   */
  private DirectoryString givenName;

  /**
   * X520name
   */
  private DirectoryString initials;

  /**
   * X520name
   */
  private DirectoryString generationQualifier;

  /**
   * businessCategory - DirectoryString(SIZE(1..128)
   */
  private DirectoryString businessCategory;

  /**
   * postalCode - DirectoryString(SIZE(1..40)
   */
  private DirectoryString postalCode;

  /**
   * dnQualifier - PrintableString (SIZE(1..64)
   */
  private Asn1PrintableString dnQualifier;

  /**
   * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
   */
  private DirectoryString pseudonym;

  /**
   * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
   */
  private Asn1GeneralizedTime dateOfBirth;

  /**
   * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
   */
  private DirectoryString placeOfBirth;

  /**
   * RFC 3039 Gender - PrintableString (SIZE(1))-- "M", "F", "m" or "f".
   */
  private Asn1PrintableString gender;

  /**
   * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2))
   *   -- ISO 3166 codes only.
   */
  private Asn1PrintableString countryOfCitizenship;

  /**
   * RFC 3039 CountryOfResidence - PrintableString (SIZE (2))
   *   -- ISO 3166 codes only.
   */
  private Asn1PrintableString countryOfResidence;

  /**
   * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
   */
  private DirectoryString nameAtBirth;

  /**
   * RFC 2256 dmdName. UnboundedDirectoryString
   */
  private DirectoryString dmdName;

  /**
   * id-at-telephoneNumber. PrintableString
   */
  private Asn1PrintableString telephoneNumber;

  /**
   * id-at-name. Naming attributes of type X520name.
   */
  private DirectoryString name;

  /**
   * Email address (RSA PKCS#9 extension) - IA5String.
   *
   * <p>Note: if you're trying to be ultra orthodox, don't use this!
   * It shouldn't be in here.
   */
  private Asn1IA5String emailAddress;

  /**
   * IA5String
   */
  private Asn1IA5String domainComponent;

  /**
   * LDAP User id. DirectoryString
   */
  private DirectoryString userid;

  /**
   * jurisdictionOfIncorporationLocalityName. DirectoryString
   */
  private DirectoryString jurIncorporationLocality;

  /**
   * jurisdictionOfIncorporationStateOrProvinceName. DirectoryString
   */
  private DirectoryString jurIncorporationState;

  /**
   * jurisdictionOfIncorporationCountryName. PrintableSting SIZE(2)
   */
  private Asn1PrintableString jurIncorporationCountry;
  // ------ END DN -----

  /**
   * more from PKCS#9. It is not an X.520 DirectoryString; it is a PKCS#9 attribute
   * and can occur in a PKCS#10 CertificationRequestInfo attribute set.
   * <pre>
   * PKCS9String ::= CHOICE {
   *     ia5String    IA5String,
   *     printableString PrintableString,
   *     utf8String   UTF8String,
   *     bmpString    BMPString
   * }
   * </pre>
   */
  private DirectoryString unstructuredName;

  /**
   * PKCS9String
   */
  private DirectoryString unstructuredAddress;

  // ----- CMC -----
  private ChangeSubjectName changeSubjectName;

  // ----- CSR -----
  private DirectoryString challengePassword;

  private Extensions extensionRequest;

  private PrivateKeyPossessionStatement statementOfPossession;

  // ----- CMS -----
  private CMSAlgorithmProtection cmsAlgorithmProtection;

  private Asn1Oid cmsContentType;

  private Asn1OctetString messageDigest;

  private AbstractAsn1Time signingTime;

  private ContentHints contentHints;

  private Asn1Integer binarySigningTime;

  // ----- PKCS#12 -----
  private SubjectKeyIdentifier localKeyId;

  private Asn1BmpString friendlyName;

  private List<Asn1Oid> oraclePkcs12TrustedKeyUsage;

  // ----- SCEP -----
  // RFC 8894: 2.16.840.1.113733.1.9.7
  private Asn1PrintableString scepTransactionId;

  // RFC 8894: 2.16.840.1.113733.1.9.2
  private Asn1PrintableString scepMessageType;

  // RFC 8894: 2.16.840.1.113733.1.9.3
  private Asn1PrintableString scepPkiStatus;

  // RFC 8894: 2.16.840.1.113733.1.9.4
  private Asn1PrintableString scepFailInfo;

  // RFC 8894: 2.16.840.1.113733.1.9.5
  private Asn1OctetString scepSenderNonce;

  // RFC 8894: 2.16.840.1.113733.1.9.6
  private Asn1OctetString scepRecipientNonce;

  // RFC 8894: 1.3.6.1.5.5.7.24.1
  private Asn1Utf8String scepFailInfoText;

  // TCG
  private TCGPlatformSpecification tcgPlatformSpecification;
  private TCGSpecificationVersion tcgCredentialSpecification;
  private TCGCredentialType tcgCredentialType;
  private PlatformConfigurationV3 tcgPlatformConfigurationV3;
  private Traits tcgPlatformConfigUriV3;
  private Traits tcgPreviousPlatformCertificates;
  private Traits tcgTbbSecurityAssertionsV3;
  private Traits tcgCryptographicAnchors;
  private Traits tcgPlatformOwnership;
  private Traits tcgManufacturingAssertions;

  private Attribute(Asn1Oid attrType, Asn1Set attrValues) {
    this.attrType = Args.notNull(attrType, "attrType");
    this.attrValues = Args.notNull(attrValues, "attrValues");
  }

  public static Attribute createNoParse(Asn1Oid attrType, Asn1Encodable singleValue) {
    return new Attribute(attrType, new Asn1Set(singleValue));
  }

  public static Attribute create(Asn1Oid attrType, Asn1Encodable singleValue)
      throws CodecException {
    Attribute r = createNoParse(attrType, singleValue);
    r.parseAttrValues();
    return r;
  }

  public static Attribute createNoParse(Asn1Oid attrType, Asn1Encodable[] singleValues) {
    return new Attribute(attrType, new Asn1Set(singleValues));
  }

  public static Attribute create(Asn1Oid attrType, Asn1Encodable[] singleValues)
      throws CodecException {
    Attribute r = createNoParse(attrType, singleValues);
    r.parseAttrValues();
    return r;
  }

  private static Attribute create2(Asn1Oid attrType, Asn1Encodable singleValue) {
    Attribute r = createNoParse(attrType, singleValue);
    r.parsed = true;
    return r;
  }

  private static Attribute create2(Asn1Oid attrType, Asn1Encodable[] singleValues) {
    Attribute r = createNoParse(attrType, singleValues);
    r.parsed = true;
    return r;
  }

  public static Attribute fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static Attribute fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid attrType = seq.getOidAt(0);
    Asn1Set attrValues = seq.getSetAt(1);
    Attribute r = new Attribute(attrType, attrValues);
    r.parseAttrValues();
    return r;
  }

  private static DirectoryString buildUtf8DirectoryString(String str) {
    return new DirectoryString(new Asn1Utf8String(str));
  }

  public static Attribute ofCountry(String value) {
    Args.notNull(value, "value");
    return ofCountry(new Asn1PrintableString(value));
  }

  public static Attribute ofCountry(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.country, value);
    r.country = value;
    return r;
  }

  //  private DirectoryString organization;
  public static Attribute ofOrganization(String value) {
    Args.notNull(value, "value");
    return ofOrganization(buildUtf8DirectoryString(value));
  }

  public static Attribute ofOrganization(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.organization, value);
    r.organization = value;
    return r;
  }

  public static Attribute ofOrganizationIdentifier(String value) {
    Args.notNull(value, "value");
    return ofOrganizationIdentifier(buildUtf8DirectoryString(value));
  }

  public static Attribute ofOrganizationIdentifier(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.organizationIdentifier, value);
    r.organizationIdentifier = value;
    return r;
  }

  public static Attribute ofOrganizationalUnit(String value) {
    Args.notNull(value, "value");
    return ofOrganizationalUnit(buildUtf8DirectoryString(value));
  }

  public static Attribute ofOrganizationalUnit(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.organizationalUnit, value);
    r.organizationalUnit = value;
    return r;
  }

  public static Attribute ofTitle(String value) {
    Args.notNull(value, "value");
    return ofTitle(buildUtf8DirectoryString(value));
  }

  public static Attribute ofTitle(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.title, value);
    r.title = value;
    return r;
  }

  public static Attribute ofCommonName(String value) {
    Args.notNull(value, "value");
    return ofCommonName(buildUtf8DirectoryString(value));
  }

  public static Attribute ofCommonName(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.commonName, value);
    r.commonName = value;
    return r;
  }

  //  private Asn1PrintableString serialNumber;
  public static Attribute ofSerialNumber(String value) {
    Args.notNull(value, "value");
    return ofSerialNumber(new Asn1PrintableString(value));
  }

  public static Attribute ofSerialNumber(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.serialNumber, value);
    r.serialNumber = value;
    return r;
  }

  public static Attribute ofStreet(String value) {
    Args.notNull(value, "value");
    return ofStreet(buildUtf8DirectoryString(value));
  }

  public static Attribute ofStreet(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.street, value);
    r.street = value;
    return r;
  }

  public static Attribute ofLocality(String value) {
    Args.notNull(value, "value");
    return ofLocality(buildUtf8DirectoryString(value));
  }

  public static Attribute ofLocality(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.locality, value);
    r.locality = value;
    return r;
  }

  public static Attribute ofState(String value) {
    Args.notNull(value, "value");
    return ofState(buildUtf8DirectoryString(value));
  }

  public static Attribute ofState(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.state, value);
    r.state = value;
    return r;
  }

  public static Attribute ofSurname(String value) {
    Args.notNull(value, "value");
    return ofSurname(buildUtf8DirectoryString(value));
  }

  public static Attribute ofSurname(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.surname, value);
    r.surname = value;
    return r;
  }

  public static Attribute ofGivenName(String value) {
    Args.notNull(value, "value");
    return ofGivenName(buildUtf8DirectoryString(value));
  }

  public static Attribute ofGivenName(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.givenName, value);
    r.givenName = value;
    return r;
  }

  public static Attribute ofInitials(String value) {
    Args.notNull(value, "value");
    return ofInitials(buildUtf8DirectoryString(value));
  }

  public static Attribute ofInitials(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.initials, value);
    r.initials = value;
    return r;
  }

  public static Attribute ofGenerationQualifier(String value) {
    Args.notNull(value, "value");
    return ofGenerationQualifier(buildUtf8DirectoryString(value));
  }

  public static Attribute ofGenerationQualifier(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.generationQualifier, value);
    r.generationQualifier = value;
    return r;
  }

  public static Attribute ofBusinessCategory(String value) {
    Args.notNull(value, "value");
    return ofBusinessCategory(buildUtf8DirectoryString(value));
  }

  public static Attribute ofBusinessCategory(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.businessCategory, value);
    r.businessCategory = value;
    return r;
  }

  public static Attribute ofPostalCode(String value) {
    Args.notNull(value, "value");
    return ofPostalCode(buildUtf8DirectoryString(value));
  }

  public static Attribute ofPostalCode(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.postalCode, value);
    r.postalCode = value;
    return r;
  }

  public static Attribute ofDnQualifier(String value) {
    Args.notNull(value, "value");
    return ofDnQualifier(new Asn1PrintableString(value));
  }

  public static Attribute ofDnQualifier(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.dnQualifier, value);
    r.dnQualifier = value;
    return r;
  }

  public static Attribute ofPseudonym(String value) {
    Args.notNull(value, "value");
    return ofPseudonym(buildUtf8DirectoryString(value));
  }

  public static Attribute ofPseudonym(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.pseudonym, value);
    r.pseudonym = value;
    return r;
  }

  /**
   * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
   */
  public static Attribute ofDateOfBirth(int year, int month, int day) {
    StringBuilder sb = new StringBuilder(15);
    checkDateOfBirth(year, month, day);

    sb.append(year); // 4 digits
    if (month < 10) {
      sb.append("0");
    }
    sb.append(month);

    if (day < 10) {
      sb.append("0");
    }
    sb.append(day);

    sb.append("000000Z");
    Asn1GeneralizedTime time = new Asn1GeneralizedTime(sb.toString());

    return ofDateOfBirth(time);
  }

  /**
   * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
   */
  public static Attribute ofDateOfBirth(Asn1GeneralizedTime value) {
    Args.notNull(value, "value");
    String text = value.getText();

    if (text.length() == 15 && text.endsWith("000000Z")) {
      int year = Integer.parseInt(text, 0, 4, 10);
      int month = Integer.parseInt(text, 4, 6, 10);
      int day = Integer.parseInt(text, 6, 8, 10);
      checkDateOfBirth(year, month, day);
    } else {
      throw new IllegalArgumentException("invalid dateOfBirth " + value);
    }

    Attribute r = create2(AttributeOIDs.dateOfBirth, value);
    r.dateOfBirth = value;
    return r;
  }

  private static void checkDateOfBirth(int year, int month, int day) {
    Args.range(year, "year", 1000, 9999);
    Args.range(month, "month", 1, 12);

    int maxDay;
    switch (month) {
      case 4:
      case 6:
      case 9:
      case 11:
        maxDay = 30;
        break;
      case 2:
        boolean isLoopYear = (year % 400 == 0) || ((year % 4 == 0) && (year % 100 != 0));
        maxDay = isLoopYear ? 29 : 28;
        break;
      default:
        maxDay = 31;
    }

    Args.range(day, "day", 1, maxDay);
  }

  public static Attribute ofPlaceOfBirth(String value) {
    Args.notNull(value, "value");
    return ofPlaceOfBirth(buildUtf8DirectoryString(value));
  }

  public static Attribute ofPlaceOfBirth(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.placeOfBirth, value);
    r.placeOfBirth = value;
    return r;
  }

  public static Attribute ofGender(String value) {
    Args.notNull(value, "value");
    return ofGender(new Asn1PrintableString(value));
  }

  public static Attribute ofGender(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.gender, value);
    r.gender = value;
    return r;
  }

  public static Attribute ofCountryOfCitizenship(String value) {
    Args.notNull(value, "value");
    return ofCountryOfCitizenship(new Asn1PrintableString(value));
  }

  public static Attribute ofCountryOfCitizenship(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.countryOfCitizenship, value);
    r.countryOfCitizenship = value;
    return r;
  }

  public static Attribute ofCountryOfResidence(String value) {
    Args.notNull(value, "value");
    return ofCountryOfResidence(new Asn1PrintableString(value));
  }

  public static Attribute ofCountryOfResidence(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.countryOfResidence, value);
    r.countryOfResidence = value;
    return r;
  }

  public static Attribute ofNameAtBirth(String value) {
    Args.notNull(value, "value");
    return ofNameAtBirth(buildUtf8DirectoryString(value));
  }

  public static Attribute ofNameAtBirth(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.nameAtBirth, value);
    r.nameAtBirth = value;
    return r;
  }

  public static Attribute ofDmdName(String value) {
    Args.notNull(value, "value");
    return ofDmdName(buildUtf8DirectoryString(value));
  }

  public static Attribute ofDmdName(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.dmdName, value);
    r.dmdName = value;
    return r;
  }

  public static Attribute ofTelephoneNumber(String value) {
    Args.notNull(value, "value");
    return ofTelephoneNumber(new Asn1PrintableString(value));
  }

  public static Attribute ofTelephoneNumber(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.telephoneNumber, value);
    r.telephoneNumber = value;
    return r;
  }

  public static Attribute ofName(String value) {
    Args.notNull(value, "value");
    return ofName(buildUtf8DirectoryString(value));
  }

  public static Attribute ofName(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.name, value);
    r.name = value;
    return r;
  }

  public static Attribute ofEmailAddress(String value) {
    Args.notNull(value, "value");
    return ofEmailAddress(new Asn1IA5String(value));
  }

  public static Attribute ofEmailAddress(Asn1IA5String value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.emailAddress, value);
    r.emailAddress = value;
    return r;
  }

  public static Attribute ofDomainComponent(String value) {
    Args.notNull(value, "value");
    return ofDomainComponent(new Asn1IA5String(value));
  }

  public static Attribute ofDomainComponent(Asn1IA5String value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.domainComponent, value);
    r.domainComponent = value;
    return r;
  }

  public static Attribute ofUserid(String value) {
    Args.notNull(value, "value");
    return ofUserid(buildUtf8DirectoryString(value));
  }

  public static Attribute ofUserid(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.userid, value);
    r.userid = value;
    return r;
  }

  public static Attribute ofJurIncorporationLocality(String value) {
    Args.notNull(value, "value");
    return ofJurIncorporationLocality(buildUtf8DirectoryString(value));
  }

  public static Attribute ofJurIncorporationLocality(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.jurIncorporationLocality, value);
    r.jurIncorporationLocality = value;
    return r;
  }

  public static Attribute ofJurIncorporationState(String value) {
    Args.notNull(value, "value");
    return ofJurIncorporationState(buildUtf8DirectoryString(value));
  }

  public static Attribute ofJurIncorporationState(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.jurIncorporationState, value);
    r.jurIncorporationState = value;
    return r;
  }

  public static Attribute ofJurIncorporationCountry(String value) {
    Args.notNull(value, "value");
    return ofJurIncorporationCountry(new Asn1PrintableString(value));
  }

  public static Attribute ofJurIncorporationCountry(Asn1PrintableString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.jurIncorporationCountry, value);
    r.jurIncorporationCountry = value;
    return r;
  }

  public static Attribute ofUnstructuredName(String value) {
    Args.notNull(value, "value");
    return ofUnstructuredName(buildUtf8DirectoryString(value));
  }

  public static Attribute ofUnstructuredName(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.unstructuredName, value);
    r.unstructuredName = value;
    return r;
  }

  public static Attribute ofUnstructuredAddress(String value) {
    Args.notNull(value, "value");
    return ofUnstructuredAddress(buildUtf8DirectoryString(value));
  }

  public static Attribute ofUnstructuredAddress(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.unstructuredAddress, value);
    r.unstructuredAddress = value;
    return r;
  }

  public static Attribute ofChangeSubjectName(ChangeSubjectName value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.id_cmc_changeSubjectName, value);
    r.changeSubjectName = value;
    return r;
  }

  public static Attribute ofChallengePassword(String value) {
    Args.notNull(value, "value");
    return ofChallengePassword(new DirectoryString(new Asn1Utf8String(value)));
  }

  public static Attribute ofChallengePassword(DirectoryString value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.pkcs9_at_challengePassword, value);
    r.challengePassword = value;
    return r;
  }

  public static Attribute ofExtensionRequest(Extensions value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.pkcs9_at_extensionRequest, value);
    r.extensionRequest = value;
    return r;
  }

  public static Attribute ofStatementOfPossession(PrivateKeyPossessionStatement value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.id_at_statementOfPossession, value);
    r.statementOfPossession = value;
    return r;
  }

  public static Attribute ofCmsAlgorithmProtection(CMSAlgorithmProtection value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.id_aa_cmsAlgorithmProtect, value);
    r.cmsAlgorithmProtection = value;
    return r;
  }

  public static Attribute ofCmsContentType(Asn1Oid value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.contentType, value);
    r.cmsContentType = value;
    return r;
  }

  public static Attribute ofMessageDigest(byte[] value) {
    Args.notNull(value, "value");
    Asn1OctetString asn1Value = new Asn1OctetString(value);
    Attribute r = create2(AttributeOIDs.messageDigest, asn1Value);
    r.messageDigest = asn1Value;
    return r;
  }

  public static Attribute ofSigningTime(Instant value) {
    Args.notNull(value, "value");
    AbstractAsn1Time asn1Value = new Time(value).toAsn1Primitive();
    Attribute r = create2(AttributeOIDs.signingTime, asn1Value);
    r.signingTime = asn1Value;
    return r;
  }

  public static Attribute ofContentHints(ContentHints value) {
    Args.notNull(value, "value");
    Attribute r = create2(AttributeOIDs.contentHint, value);
    r.contentHints = value;
    return r;
  }

  public static Attribute ofBinarySigningTime(Instant value) {
    Args.notNull(value, "value");
    Asn1Integer asn1Value = new Asn1Integer(value.getEpochSecond());
    Attribute r = create2(AttributeOIDs.binarySigningTime, asn1Value);
    r.binarySigningTime = asn1Value;
    return r;
  }

  public static Attribute ofLocalKeyId(byte[] value) {
    Args.notNull(value, "value");
    SubjectKeyIdentifier asn1Value = new SubjectKeyIdentifier(value);
    Attribute r = create2(AttributeOIDs.pkcs_9_at_localKeyId, asn1Value);
    r.localKeyId = asn1Value;
    return r;
  }

  public static Attribute ofFriendlyName(String value) {
    Args.notNull(value, "value");
    Asn1BmpString asn1Value = new Asn1BmpString(value);
    Attribute r = create2(AttributeOIDs.pkcs_9_at_friendlyName, asn1Value);
    r.friendlyName = asn1Value;
    return r;
  }

  // caution: multiple-valued attribute
  public static Attribute ofOraclePkcs12TrustedKeyUsage(List<Asn1Oid> value) {
    if (value == null) {
      value = Collections.emptyList();
    }
    Args.noNullElements(value, "value");

    Attribute r = create2(AttributeOIDs.id_oracle_pkcs12_trusted_key_usage,
        value.toArray(new Asn1Oid[0]));
    r.oraclePkcs12TrustedKeyUsage = value;
    return r;
  }

  public static Attribute ofScepTransactionId(String value) {
    Args.notNull(value, "value");
    Asn1PrintableString asn1Value = new Asn1PrintableString(value);
    Attribute r = create2(AttributeOIDs.scep_transactionId, asn1Value);
    r.scepTransactionId = asn1Value;
    return r;
  }

  public static Attribute ofScepMessageType(int value) {
    Asn1PrintableString asn1Value = new Asn1PrintableString(Integer.toString(value));
    Attribute r = create2(AttributeOIDs.scep_messageType, asn1Value);
    r.scepMessageType = asn1Value;
    return r;
  }

  public static Attribute ofScepPkiStatus(int value) {
    Asn1PrintableString asn1Value = new Asn1PrintableString(Integer.toString(value));
    Attribute r = create2(AttributeOIDs.scep_pkiStatus, asn1Value);
    r.scepPkiStatus = asn1Value;
    return r;
  }

  public static Attribute ofScepFailInfo(int value) {
    Asn1PrintableString asn1Value = new Asn1PrintableString(Integer.toString(value));
    Attribute r = create2(AttributeOIDs.scep_failInfo, asn1Value);
    r.scepFailInfo = asn1Value;
    return r;
  }

  public static Attribute ofScepSenderNonce(byte[] value) {
    Args.notNull(value, "value");
    Asn1OctetString asn1Value = new Asn1OctetString(value);
    Attribute r = create2(AttributeOIDs.scep_senderNonce, asn1Value);
    r.scepSenderNonce = asn1Value;
    return r;
  }

  public static Attribute ofScepRecipientNonce(byte[] value) {
    Args.notNull(value, "value");
    Asn1OctetString asn1Value = new Asn1OctetString(value);
    Attribute r = create2(AttributeOIDs.scep_recipientNonce, asn1Value);
    r.scepRecipientNonce = asn1Value;
    return r;
  }

  public static Attribute ofScepFailInfoText(String value) {
    Args.notNull(value, "value");
    Asn1Utf8String asn1Value = new Asn1Utf8String(value);
    Attribute r = create2(AttributeOIDs.scep_failInfoText, asn1Value);
    r.scepFailInfoText = asn1Value;
    return r;
  }

  // ----- TCG -----
  public static Attribute ofTcgPlatformSpecification(TCGPlatformSpecification value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_tcgPlatformSpecification, value);
    r.tcgPlatformSpecification = value;
    return r;
  }

  public static Attribute ofTcgCredentialSpecification(TCGSpecificationVersion value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_tcgCredentialSpecification, value);
    r.tcgCredentialSpecification = value;
    return r;
  }

  public static Attribute ofTcgCredentialType(TCGCredentialType value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_tcgCredentialType, value);
    r.tcgCredentialType = value;
    return r;
  }

  public static Attribute ofTcgPlatformConfigurationV3(PlatformConfigurationV3 value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_platformConfiguration_v3, value);
    r.tcgPlatformConfigurationV3 = value;
    return r;
  }

  public static Attribute ofTcgPlatformConfigUriV3(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_platformConfigUri_v3, value);
    r.tcgPlatformConfigUriV3 = value;
    return r;
  }

  public static Attribute ofTcgPreviousPlatformCertificates(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_previousPlatformCertificates, value);
    r.tcgPreviousPlatformCertificates = value;
    return r;
  }

  public static Attribute ofTcgTbbSecurityAssertionsV3(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_tbbSecurityAssertions_v3, value);
    r.tcgTbbSecurityAssertionsV3 = value;
    return r;
  }

  public static Attribute ofTcgCryptographicAnchors(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_cryptographicAnchors, value);
    r.tcgCryptographicAnchors = value;
    return r;
  }

  public static Attribute ofTcgPlatformOwnership(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_platformOwnership, value);
    r.tcgPlatformOwnership = value;
    return r;
  }

  public static Attribute ofTcgManufacturingAssertions(Traits value) {
    Args.notNull(value, "value");
    Attribute r = create2(TcgOIDs.tcg_at_manufacturingAssertions, value);
    r.tcgManufacturingAssertions = value;
    return r;
  }

  public Asn1Oid getAttrType() {
    return attrType;
  }

  public Asn1Set getAttrValues() {
    return attrValues;
  }

  public Asn1Primitive getFirstAttrValue() {
    return attrValues.getObjectAt(0);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(attrType, attrValues);
  }

  private static String fromDirectoryString(DirectoryString dirStr) {
    return dirStr == null ? null : dirStr.string();
  }

  public DirectoryString getChallengePassword() {
    return challengePassword;
  }

  public String challengePassword() {
    return fromDirectoryString(challengePassword);
  }

  public Extensions getExtensionRequest() {
    return extensionRequest;
  }

  public PrivateKeyPossessionStatement getStatementOfPossession() {
    return statementOfPossession;
  }

  public CMSAlgorithmProtection getCmsAlgorithmProtection() {
    return cmsAlgorithmProtection;
  }

  public Asn1Oid getCmsContentType() {
    return cmsContentType;
  }

  public Asn1OctetString getMessageDigest() {
    return messageDigest;
  }

  public byte[] messageDigest() {
    return Asn1Util.fromAsn1(messageDigest);
  }

  public AbstractAsn1Time getSigningTime() {
    return signingTime;
  }

  public Instant signingTime() {
    return Asn1Util.fromAsn1(signingTime);
  }

  public ContentHints getContentHints() {
    return contentHints;
  }

  public Asn1Integer getBinarySigningTime() {
    return binarySigningTime;
  }

  public Instant binarySigningTime() {
    return binarySigningTime == null ? null
        : Instant.ofEpochSecond(binarySigningTime.longValueExact());
  }

  public SubjectKeyIdentifier getLocalKeyId() {
    return localKeyId;
  }

  public byte[] localKeyId() {
    return localKeyId == null ? null : localKeyId.getKeyIdentifier();
  }

  public Asn1BmpString getFriendlyName() {
    return friendlyName;
  }

  public String friendlyName() {
    return Asn1Util.fromAsn1(friendlyName);
  }

  public List<Asn1Oid> getOraclePkcs12TrustedKeyUsage() {
    return oraclePkcs12TrustedKeyUsage;
  }

  public Asn1PrintableString getScepTransactionId() {
    return scepTransactionId;
  }

  public String scepTransactionId() {
    return Asn1Util.fromAsn1(scepTransactionId);
  }

  public Asn1PrintableString getScepMessageType() {
    return scepMessageType;
  }

  public Integer scepMessageType() {
    return scepMessageType == null ? null : Integer.parseInt(scepMessageType.getString());
  }

  public Asn1PrintableString getScepPkiStatus() {
    return scepPkiStatus;
  }

  public Integer scepPkiStatus() {
    return scepPkiStatus == null ? null : Integer.parseInt(scepPkiStatus.getString());
  }

  public Asn1PrintableString getScepFailInfo() {
    return scepFailInfo;
  }

  public Integer scepFailInfo() {
    return scepFailInfo == null ? null : Integer.parseInt(scepFailInfo.getString());
  }

  public Asn1OctetString getScepSenderNonce() {
    return scepSenderNonce;
  }

  public byte[] scepSenderNonce() {
    return Asn1Util.fromAsn1(scepSenderNonce);
  }

  public Asn1OctetString getScepRecipientNonce() {
    return scepRecipientNonce;
  }

  public byte[] scepRecipientNonce() {
    return Asn1Util.fromAsn1(scepRecipientNonce);
  }

  public Asn1Utf8String getScepFailInfoText() {
    return scepFailInfoText;
  }

  public String scepFailInfoText() {
    return Asn1Util.fromAsn1(scepFailInfoText);
  }

  public Asn1PrintableString getCountry() {
    return country;
  }

  public String country() {
    return Asn1Util.fromAsn1(country);
  }

  public DirectoryString getOrganization() {
    return organization;
  }

  public String organization() {
    return fromDirectoryString(organization);
  }

  public DirectoryString getOrganizationIdentifier() {
    return organizationIdentifier;
  }

  public String organizationIdentifier() {
    return fromDirectoryString(organizationIdentifier);
  }

  public DirectoryString getOrganizationalUnit() {
    return organizationalUnit;
  }

  public String organizationalUnit() {
    return fromDirectoryString(organizationalUnit);
  }

  public DirectoryString getTitleAttr() {
    return title;
  }

  public String titleAttr() {
    return fromDirectoryString(title);
  }

  public DirectoryString getCommonName() {
    return commonName;
  }

  public String commonName() {
    return fromDirectoryString(commonName);
  }

  public Asn1PrintableString getSerialNumber() {
    return serialNumber;
  }

  public String serialNumber() {
    return Asn1Util.fromAsn1(serialNumber);
  }

  public DirectoryString getStreet() {
    return street;
  }

  public String street() {
    return fromDirectoryString(street);
  }

  public DirectoryString getLocality() {
    return locality;
  }

  public String locality() {
    return fromDirectoryString(locality);
  }

  public DirectoryString getState() {
    return state;
  }

  public String state() {
    return fromDirectoryString(state);
  }

  public DirectoryString getSurname() {
    return surname;
  }

  public String surname() {
    return fromDirectoryString(surname);
  }

  public DirectoryString getGivenName() {
    return givenName;
  }

  public String givenName() {
    return fromDirectoryString(givenName);
  }

  public DirectoryString getInitials() {
    return initials;
  }

  public String initials() {
    return fromDirectoryString(initials);
  }

  public DirectoryString getGenerationQualifier() {
    return generationQualifier;
  }

  public String generationQualifier() {
    return fromDirectoryString(generationQualifier);
  }

  public DirectoryString getBusinessCategory() {
    return businessCategory;
  }

  public String businessCategory() {
    return fromDirectoryString(businessCategory);
  }

  public DirectoryString getPostalCode() {
    return postalCode;
  }

  public String postalCode() {
    return fromDirectoryString(postalCode);
  }

  public Asn1PrintableString getDnQualifier() {
    return dnQualifier;
  }

  public String dnQualifier() {
    return Asn1Util.fromAsn1(dnQualifier);
  }

  public DirectoryString getPseudonym() {
    return pseudonym;
  }

  public String pseudonym() {
    return fromDirectoryString(pseudonym);
  }

  public Asn1GeneralizedTime getDateOfBirth() {
    return dateOfBirth;
  }

  public DirectoryString getPlaceOfBirth() {
    return placeOfBirth;
  }

  public String placeOfBirth() {
    return fromDirectoryString(placeOfBirth);
  }

  public Asn1PrintableString getGender() {
    return gender;
  }

  public String gender() {
    return Asn1Util.fromAsn1(gender);
  }

  public Asn1PrintableString getCountryOfCitizenship() {
    return countryOfCitizenship;
  }

  public String countryOfCitizenship() {
    return Asn1Util.fromAsn1(countryOfCitizenship);
  }

  public Asn1PrintableString getCountryOfResidence() {
    return countryOfResidence;
  }

  public String countryOfResidence() {
    return Asn1Util.fromAsn1(countryOfResidence);
  }

  public DirectoryString getNameAtBirth() {
    return nameAtBirth;
  }

  public String nameAtBirth() {
    return fromDirectoryString(nameAtBirth);
  }

  public DirectoryString getDmdName() {
    return dmdName;
  }

  public Asn1PrintableString getTelephoneNumber() {
    return telephoneNumber;
  }

  public DirectoryString getName() {
    return name;
  }

  public Asn1IA5String getEmailAddress() {
    return emailAddress;
  }

  public Asn1IA5String getDomainComponent() {
    return domainComponent;
  }

  public DirectoryString getUserid() {
    return userid;
  }

  public DirectoryString getJurIncorporationLocality() {
    return jurIncorporationLocality;
  }

  public DirectoryString getJurIncorporationState() {
    return jurIncorporationState;
  }

  public Asn1PrintableString getJurIncorporationCountry() {
    return jurIncorporationCountry;
  }

  public DirectoryString getUnstructuredName() {
    return unstructuredName;
  }

  public DirectoryString getUnstructuredAddress() {
    return unstructuredAddress;
  }

  public ChangeSubjectName getChangeSubjectName() {
    return changeSubjectName;
  }

  public TCGPlatformSpecification getTcgPlatformSpecification() {
    return tcgPlatformSpecification;
  }

  public TCGSpecificationVersion getTcgCredentialSpecification() {
    return tcgCredentialSpecification;
  }

  public TCGCredentialType getTcgCredentialType() {
    return tcgCredentialType;
  }

  public PlatformConfigurationV3 getTcgPlatformConfigurationV3() {
    return tcgPlatformConfigurationV3;
  }

  public Traits getTcgPlatformConfigUriV3() {
    return tcgPlatformConfigUriV3;
  }

  public Traits getTcgPreviousPlatformCertificates() {
    return tcgPreviousPlatformCertificates;
  }

  public Traits getTcgTbbSecurityAssertionsV3() {
    return tcgTbbSecurityAssertionsV3;
  }

  public Traits getTcgCryptographicAnchors() {
    return tcgCryptographicAnchors;
  }

  public Traits getTcgPlatformOwnership() {
    return tcgPlatformOwnership;
  }

  public Traits getTcgManufacturingAssertions() {
    return tcgManufacturingAssertions;
  }

  private void parseAttrValues() throws CodecException {
    if (parsed) {
      return;
    }

    String id = attrType.getId();
    if (id.equals(AttributeOIDs.pkcs9_at_challengePassword.getId())) {
      challengePassword = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.pkcs9_at_extensionRequest.getId())) {
      extensionRequest = Extensions.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(AttributeOIDs.id_at_statementOfPossession.getId())) {
      statementOfPossession = PrivateKeyPossessionStatement.fromAsn1(
         getFirstAttrValue().asSequence());
    } else if (id.equals(AttributeOIDs.id_aa_cmsAlgorithmProtect.getId())) {
      cmsAlgorithmProtection = CMSAlgorithmProtection.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(AttributeOIDs.contentType.getId())) {
      cmsContentType = getFirstAttrValue().asOid();
    } else if (id.equals(AttributeOIDs.messageDigest.getId())) {
      messageDigest = getFirstAttrValue().asOctetString();
    } else if (id.equals(AttributeOIDs.binarySigningTime.getId())) {
      binarySigningTime = Asn1Integer.checkNonNegative(getFirstAttrValue().asInteger());
    } else if (id.equals(AttributeOIDs.signingTime.getId())) {
      signingTime = getFirstAttrValue().asTime();
    } else if (id.equals(AttributeOIDs.contentHint.getId())) {
      contentHints = ContentHints.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(AttributeOIDs.pkcs_9_at_localKeyId.getId())) {
      localKeyId = SubjectKeyIdentifier.fromAsn1(getFirstAttrValue().asOctetString());
    } else if (id.equals(AttributeOIDs.pkcs_9_at_friendlyName.getId())) {
      friendlyName = getFirstAttrValue().asBmpString();
    } else if (id.equals(AttributeOIDs.id_oracle_pkcs12_trusted_key_usage.getId())) {
      oraclePkcs12TrustedKeyUsage = OidSet.fromAsn1(0, attrValues).getEntries();
    } else if (id.equals(AttributeOIDs.scep_transactionId.getId())) {
      scepTransactionId = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.scep_messageType.getId())) {
      scepMessageType = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.scep_pkiStatus.getId())) {
      scepPkiStatus = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.scep_failInfo.getId())) {
      scepFailInfo = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.scep_senderNonce.getId())) {
      scepSenderNonce = getFirstAttrValue().asOctetString();
    } else if (id.equals(AttributeOIDs.scep_recipientNonce.getId())) {
      scepRecipientNonce = getFirstAttrValue().asOctetString();
    } else if (id.equals(AttributeOIDs.scep_failInfoText.getId())) {
      scepFailInfoText = getFirstAttrValue().asUtf8String();
    } else if (id.equals(AttributeOIDs.country.getId())) {
      country = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.organization.getId())) {
      organization = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.organizationIdentifier.getId())) {
      organizationIdentifier = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.organizationalUnit.getId())) {
      organizationalUnit = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.title.getId())) {
      title = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.commonName.getId())) {
      commonName = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.serialNumber.getId())) {
      serialNumber = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.street.getId())) {
      street = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.locality.getId())) {
      locality = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.state.getId())) {
      state = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.surname.getId())) {
      surname = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.givenName.getId())) {
      givenName = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.initials.getId())) {
      initials = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.generationQualifier.getId())) {
      generationQualifier = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.businessCategory.getId())) {
      businessCategory = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.postalCode.getId())) {
      postalCode = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.dnQualifier.getId())) {
      dnQualifier = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.pseudonym.getId())) {
      pseudonym = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.dateOfBirth.getId())) {
      dateOfBirth = getFirstAttrValue().asGeneralizedTime();
    } else if (id.equals(AttributeOIDs.placeOfBirth.getId())) {
      placeOfBirth = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.gender.getId())) {
      gender = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.countryOfCitizenship.getId())) {
      countryOfCitizenship = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.countryOfResidence.getId())) {
      countryOfResidence = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.nameAtBirth.getId())) {
      nameAtBirth = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.dmdName.getId())) {
      dmdName = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.telephoneNumber.getId())) {
      telephoneNumber = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.name.getId())) {
      name = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.emailAddress.getId())) {
      emailAddress = getFirstAttrValue().asIA5String();
    } else if (id.equals(AttributeOIDs.domainComponent.getId())) {
      domainComponent = getFirstAttrValue().asIA5String();
    } else if (id.equals(AttributeOIDs.userid.getId())) {
      userid = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.jurIncorporationLocality.getId())) {
      jurIncorporationLocality = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.jurIncorporationState.getId())) {
      jurIncorporationState = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.jurIncorporationCountry.getId())) {
      jurIncorporationCountry = getFirstAttrValue().asPrintableString();
    } else if (id.equals(AttributeOIDs.unstructuredName.getId())) {
      unstructuredName = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.unstructuredAddress.getId())) {
      unstructuredAddress = DirectoryString.fromAsn1(getFirstAttrValue());
    } else if (id.equals(AttributeOIDs.id_cmc_changeSubjectName.getId())) {
      changeSubjectName = ChangeSubjectName.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_tcgPlatformSpecification.getId())) {
      tcgPlatformSpecification = TCGPlatformSpecification.fromAsn1(
          getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_tcgCredentialSpecification.getId())) {
      tcgCredentialSpecification = TCGSpecificationVersion.fromAsn1(
          getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_tcgCredentialType.getId())) {
      tcgCredentialType = TCGCredentialType.fromAsn1(
          getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_platformConfiguration_v3.getId())) {
      tcgPlatformConfigurationV3 = PlatformConfigurationV3.fromAsn1(
          getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_platformConfigUri_v3.getId())) {
      tcgPlatformConfigUriV3 = Traits.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_previousPlatformCertificates.getId())) {
      tcgPreviousPlatformCertificates = Traits.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_tbbSecurityAssertions_v3.getId())) {
      tcgTbbSecurityAssertionsV3 = Traits.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_cryptographicAnchors.getId())) {
      tcgCryptographicAnchors = Traits.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_platformOwnership.getId())) {
      tcgPlatformOwnership = Traits.fromAsn1(getFirstAttrValue().asSequence());
    } else if (id.equals(TcgOIDs.tcg_at_manufacturingAssertions.getId())) {
      tcgManufacturingAssertions = Traits.fromAsn1(getFirstAttrValue().asSequence());
    }

    parsed = true;
  }

  @Override
  public int hashCode() {
    return attrType.hashCode() * 31 + attrValues.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Attribute)) {
      return false;
    }

    Attribute b = (Attribute) obj;
    return attrType.equals(b.attrType) && attrValues.equals(b.attrValues);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    attrType.toStringNoLineSep(buf, indentLevel, "attrType", true);
    if (oraclePkcs12TrustedKeyUsage != null) {
      return new OidSeq(0, oraclePkcs12TrustedKeyUsage).toString(buf, indentLevel + 1);
    } else {
      Asn1Encodable singleValue = parsedSingleValue();
      if (singleValue == null) {
        return attrValues.toString(buf, indentLevel + 1);
      } else {
        return singleValue.toString(buf, indentLevel + 1);
      }
    }
  }

  private Asn1Encodable parsedSingleValue() {
    return country != null ? country
        : organization != null ? organization
        : organizationIdentifier != null ? organizationIdentifier
        : organizationalUnit != null ? organizationalUnit
        : title != null ? title
        : commonName != null ? commonName
        : serialNumber != null ? serialNumber
        : street != null ? street
        : locality != null ? locality
        : state != null ? state
        : surname != null ? surname
        : givenName != null ? givenName
        : initials != null ? initials
        : generationQualifier != null ? generationQualifier
        : businessCategory != null ? businessCategory
        : postalCode != null ? postalCode
        : dnQualifier != null ? dnQualifier
        : pseudonym != null ? pseudonym
        : dateOfBirth != null ? dateOfBirth
        : placeOfBirth != null ? placeOfBirth
        : gender != null ? gender
        : countryOfCitizenship != null ? countryOfCitizenship
        : countryOfResidence != null ? countryOfResidence
        : nameAtBirth != null ? nameAtBirth
        : dmdName != null ? dmdName
        : telephoneNumber != null ? telephoneNumber
        : name != null ? name
        : emailAddress != null ? emailAddress
        : domainComponent != null ? domainComponent
        : userid != null ? userid
        : jurIncorporationLocality != null ? jurIncorporationLocality
        : jurIncorporationState != null ? jurIncorporationState
        : jurIncorporationCountry != null ? jurIncorporationCountry
        : unstructuredName != null ? unstructuredName
        : unstructuredAddress != null ? unstructuredAddress
        : changeSubjectName != null ? changeSubjectName
        : extensionRequest != null ? extensionRequest
        : statementOfPossession != null ? statementOfPossession
        : cmsAlgorithmProtection != null ? cmsAlgorithmProtection
        : cmsContentType != null ? cmsContentType
        : messageDigest != null ? messageDigest
        : signingTime != null ? signingTime
        : contentHints != null ? contentHints
        : binarySigningTime != null ? binarySigningTime
        : localKeyId != null ? localKeyId
        : friendlyName != null ? friendlyName
        // : oraclePkcs12TrustedKeyUsage != null ? oraclePkcs12TrustedKeyUsage
        : scepTransactionId != null ? scepTransactionId
        : scepMessageType != null ? scepMessageType
        : scepPkiStatus != null ? scepPkiStatus
        : scepFailInfo != null ? scepFailInfo
        : scepSenderNonce != null ? scepSenderNonce
        : scepRecipientNonce != null ? scepRecipientNonce
        : scepFailInfoText != null ? scepFailInfoText
        : tcgPlatformSpecification != null ? tcgPlatformSpecification
        : tcgCredentialSpecification != null ? tcgCredentialSpecification
        : tcgCredentialType != null ? tcgCredentialType
        : tcgPlatformConfigurationV3 != null ? tcgPlatformConfigurationV3
        : tcgPlatformConfigUriV3 != null ? tcgPlatformConfigUriV3
        : tcgPreviousPlatformCertificates != null ? tcgPreviousPlatformCertificates
        : tcgTbbSecurityAssertionsV3 != null ? tcgTbbSecurityAssertionsV3
        : tcgCryptographicAnchors != null ? tcgCryptographicAnchors
        : tcgPlatformOwnership != null ? tcgPlatformOwnership
        : tcgManufacturingAssertions != null ? tcgManufacturingAssertions
        : null;
  }

}
