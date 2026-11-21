// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.registry;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Values of the C509 RDN Attributes registry (draft-ietf-cose-cbor-encoded-cert-21, Section 8.6,
 * Figure 10). The value 24 (postalAddress) is not assigned in Figure 10 and is therefore disabled.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstRDNAttributeType {

  private ConstRDNAttributeType() {
  }

  /** Email Address, identifier {@code emailAddress}, OID {@code 1.2.840.113549.1.9.1}. */
  public static final long emailAddress = 0;

  /** Common Name, identifiers {@code commonName}, {@code cn}, OID {@code 2.5.4.3}. */
  public static final long commonName = 1;

  /** Surname, identifiers {@code surname}, {@code sn}, OID {@code 2.5.4.4}. */
  public static final long surname = 2;

  /** Serial Number, identifier {@code serialNumber}, OID {@code 2.5.4.5}. */
  public static final long serialNumber = 3;

  /** Country, identifiers {@code countryName}, {@code c}, OID {@code 2.5.4.6}. */
  public static final long country = 4;

  /**
   * Locality, identifiers {@code localityName}, {@code locality}, {@code l}, OID {@code 2.5.4.7}.
   */
  public static final long locality = 5;

  /**
   * State or Province, identifiers {@code stateOrProvinceName}, {@code st}, OID {@code 2.5.4.8}.
   */
  public static final long state = 6;

  /** Street Address, identifiers {@code streetAddress}, {@code street}, OID {@code 2.5.4.9}. */
  public static final long street = 7;

  /** Organization, identifiers {@code organizationName}, {@code o}, OID {@code 2.5.4.10}. */
  public static final long organization = 8;

  /**
   * Organizational Unit, identifiers {@code organizationalUnitName}, {@code ou}, OID
   * {@code 2.5.4.11}.
   */
  public static final long organizationalUnit = 9;

  /** Title, identifier {@code title}, OID {@code 2.5.4.12}. */
  public static final long title = 10;

  /** Business Category, identifier {@code businessCategory}, OID {@code 2.5.4.15}. */
  public static final long businessCategory = 11;

  /** Postal Code, identifier {@code postalCode}, OID {@code 2.5.4.17}. */
  public static final long postalCode = 12;

  /** Given Name, identifier {@code givenName}, OID {@code 2.5.4.42}. */
  public static final long givenName = 13;

  /** Initials, identifier {@code initials}, OID {@code 2.5.4.43}. */
  public static final long initials = 14;

  /** Generation Qualifier, identifier {@code generationQualifier}, OID {@code 2.5.4.44}. */
  public static final long generationQualifier = 15;

  /** DN Qualifier, identifier {@code dnQualifier}, OID {@code 2.5.4.46}. */
  public static final long dnQualifier = 16;

  /** Pseudonym, identifier {@code pseudonym}, OID {@code 2.5.4.65}. */
  public static final long pseudonym = 17;

  /** Organization Identifier, identifier {@code organizationIdentifier}, OID {@code 2.5.4.97}. */
  public static final long organizationIdentifier = 18;

  /**
   * Jurisdiction Locality Name, identifier {@code jurisdictionLocalityName}, OID
   * {@code 1.3.6.1.4.1.311.60.2.1.1}.
   */
  public static final long jurisdictionLocalityName = 19;

  /**
   * Jurisdiction State or Province Name, identifier {@code jurisdictionStateOrProvinceName}, OID
   * {@code 1.3.6.1.4.1.311.60.2.1.2}.
   */
  public static final long jurisdictionStateOrProvinceName = 20;

  /**
   * Jurisdiction Country Name, identifier {@code jurisdictionCountryName}, OID
   * {@code 1.3.6.1.4.1.311.60.2.1.3}.
   */
  public static final long jurisdictionCountryName = 21;

  /**
   * Domain Component, identifiers {@code domainComponent}, {@code dc}, OID
   * {@code 0.9.2342.19200300.100.1.25}.
   */
  public static final long domainComponent = 22;

  /** Postal Address, OID {@code 2.5.4.16}. Not assigned in Figure 10. */
  // public static final long postalAddress = 24;

  /** Name, identifier {@code name}, OID {@code 2.5.4.41}. */
  public static final long name = 25;

  /** Telephone Number, identifier {@code telephoneNumber}, OID {@code 2.5.4.20}. */
  public static final long telephoneNumber = 26;

  /** Directory Management Domain Name, identifier {@code dmdName}, OID {@code 2.5.4.54}. */
  public static final long dmdName = 27;

  /** userid, identifier {@code uid}, OID {@code 0.9.2342.19200300.100.1.1}. */
  public static final long userid = 28;

  /** Unstructured Name, identifier {@code unstructuredName}, OID {@code 1.2.840.113549.1.9.2}. */
  public static final long unstructuredName = 29;

  /**
   * Unstructured Address, identifier {@code unstructuredAddress}, OID {@code 1.2.840.113549.1.9.8}.
   */
  public static final long unstructuredAddress = 30;

  private static final Map<Long, String> codeToName = new HashMap<>();

  static {
    f(emailAddress,        "emailAddress");
    f(commonName,          "commonName");
    f(surname,             "surname");
    f(serialNumber,        "serialNumber");
    f(country,             "country");
    f(locality,            "locality");
    f(state,               "state");
    f(street,              "street");
    f(organization,        "organization");
    f(organizationalUnit,  "organizationalUnit");
    f(title,               "title");
    f(businessCategory,    "businessCategory");
    f(postalCode,          "postalCode");
    f(givenName,           "givenName");
    f(initials,            "initials");
    f(generationQualifier, "generationQualifier");
    f(dnQualifier,         "DNQualifier");
    f(pseudonym,           "pseudonym");
    f(organizationIdentifier, "organizationIdentifier");
    f(jurisdictionLocalityName, "jurisdictionLocalityName");
    f(jurisdictionStateOrProvinceName, "jurisdictionStateOrProvinceName");
    f(jurisdictionCountryName, "jurisdictionCountryName");
    f(domainComponent,     "domainComponent");
    // f(postalAddress,       "postalAddress");
    f(name,                "name");
    f(telephoneNumber,     "telephoneNumber");
    f(dmdName,             "DMDName");
    f(userid,              "userID");
    f(unstructuredName,    "unstructuredName");
    f(unstructuredAddress, "unstructuredAddress");
  }

  /** The registered names and the names of the constants, in canonical form. */
  private static final Map<String, Long> ALIASES = new HashMap<>();

  static {
    for (Map.Entry<Long, String> entry : codeToName.entrySet()) {
      addAlias(entry.getValue(), entry.getKey());
    }

    for (Field field : ConstRDNAttributeType.class.getFields()) {
      int mod = field.getModifiers();
      if (field.getType() == long.class && Modifier.isStatic(mod) && Modifier.isFinal(mod)) {
        try {
          addAlias(field.getName(), field.getLong(null));
        } catch (IllegalAccessException ex) {
          throw new IllegalStateException(ex);
        }
      }
    }
  }

  private static void addAlias(String name, long code) {
    Long prev = ALIASES.putIfAbsent(ConstRegistry.canonicalName(name), code);
    if (prev != null && prev != code) {
      throw new IllegalStateException("RDN attribute: name " + name + " of code " + code
          + " is already used by code " + prev);
    }
  }

  /**
   * Returns the code for the name of the constant (e.g. {@code organizationalUnit}, case,
   * spaces, dashes and underscores are ignored), the registered name, or the decimal code.
   *
   * @param nameOrCode the name or the decimal code.
   * @return the code, or {@code null} if the name is unknown.
   */
  public static Long code(String nameOrCode) {
    String text = nameOrCode.trim();
    try {
      return Long.parseLong(text);
    } catch (NumberFormatException ex) {
      return ALIASES.get(ConstRegistry.canonicalName(text));
    }
  }

  private static void f(long code, String name) {
    if (codeToName.containsKey(code)) {
      throw new IllegalArgumentException("duplicated code " + code);
    }
    codeToName.put(code, name);
  }

  public static String describe(long code) {
    return name(code) + " (" + code + ")";
  }

  public static String name(long code) {
    String name = codeToName.get(code);
    return name == null ? "unknown" : name;
  }

  public static String getShortName(long code) {
    if (code == emailAddress) {
      return "E";
    } else if (code == commonName) {
      return "CN";
    } else if (code == surname) {
      return "SN";
    } else if (code == serialNumber) {
      return "serialNumber";
    } else if (code == country) {
      return "C";
    } else if (code == locality) {
      return "L";
    } else if (code == state) {
      return "S";
    } else if (code == street) {
      return "street";
    } else if (code == organization) {
      return "O";
    } else if (code == organizationalUnit) {
      return "OU";
    } else if (code == title) {
      return "title";
    } else if (code == businessCategory) {
      return "businessCategory";
    } else if (code == postalCode) {
      return "postalCode";
    } else if (code == givenName) {
      return "GN";
    } else if (code == initials) {
      return "initials";
    } else if (code == generationQualifier) {
      return "generationQualifier";
    } else if (code == dnQualifier) {
      return "DNQualifier";
    } else if (code == pseudonym) {
      return "pseudonym";
    } else if (code == organizationIdentifier) {
      return "organizationIdentifier";
    } else if (code == jurisdictionLocalityName) {
      return "jurisdictionLocalityName";
    } else if (code == jurisdictionStateOrProvinceName) {
      return "jurisdictionStateOrProvinceName";
    } else if (code == jurisdictionCountryName) {
      return "jurisdictionCountryName";
    } else if (code == domainComponent) {
      return "DC";
    //} else if (code == postalAddress) {
    //  return "postalAddress";
    } else if (code == name) {
      return "name";
    } else if (code == telephoneNumber) {
      return "telephoneNumber";
    } else if (code == dmdName) {
      return "DMDName";
    } else if (code == userid) {
      return "userid";
    } else if (code == unstructuredName) {
      return "unstructuredName";
    } else if (code == unstructuredAddress) {
      return "unstructuredAddress";
    } else {
      return Long.toString(code);
    }
  }

  public static long getCode(String shortName) {
    shortName = shortName.toLowerCase(Locale.ROOT);
    switch (shortName) {
      case "emailaddress":
      case "e":
      case "email":
        return emailAddress;
      case "commonname":
      case "cn":
        return commonName;
      case "surname":
        return surname;
      case "serialnumber":
      case "sn":
        return serialNumber;
      case "country":
      case "c":
        return country;
      case "locality":
      case "l":
        return locality;
      case "state":
      case "s":
        return state;
      case "streetaddress":
      case "street":
        return street;
      case "organization":
      case "o":
        return organization;
      case "organizationalunit":
      case "ou":
        return organizationalUnit;
      case "title":
        return title;
      case "businesscategory":
        return businessCategory;
      case "postalcode":
        return postalCode;
      case "givenname":
      case "gn":
        return givenName;
      case "initials":
      case "i":
        return initials;
      case "generationqualifier":
        return generationQualifier;
      case "dnq":
      case "dnqualifier":
        return dnQualifier;
      case "pseudonym":
        return pseudonym;
      case "organizationidentifier":
      case "oi":
      case "orgid":
      return organizationIdentifier;
      case "jurincorporationlocality":
      case "jil":
        return jurisdictionLocalityName;
      case "jurincorporationstate":
      case "jis":
        return jurisdictionStateOrProvinceName;
      case "jurincorporationcountry":
      case "jic":
        return jurisdictionCountryName;
      case "domaincomponent":
      case "dc":
        return domainComponent;
      //case "postaladdress":
      //  return postalAddress;
      case "name":
        return name;
      case "telephonenumber":
        return telephoneNumber;
      case "dmdname":
        return dmdName;
      case "userid":
      case "uid":
        return userid;
      case "unstructurenname":
        return unstructuredName;
      case "unstructuredaddress":
        return unstructuredAddress;
      default:
        try {
          return Long.parseLong(shortName);
        } catch (Exception e) {
          throw new IllegalArgumentException("unknown name '" + shortName + "'");
        }
    }
  }

}
