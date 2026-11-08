// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x500;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.asn1.oid.X509OIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.codec.util.ToStringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The X.500 Name object.
 * <pre>
 * Name ::= CHOICE { RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class X500Name extends Asn1Encodable {

  private static final Map<String, Asn1Oid> nameOidMap = new HashMap<>();

  private static final Map<String, String> oidNameMap = new HashMap<>();

  /**
   * country code - StringType(SIZE(2))
   */
  public static final Asn1Oid C = oid("2.5.4.6", "C");

  /**
   * organization - StringType(SIZE(1..64))
   */
  public static final Asn1Oid O = oid("2.5.4.10", "O");

  /**
   * organizational unit name - StringType(SIZE(1..64))
   */
  public static final Asn1Oid OU = oid("2.5.4.11", "OU");

  /**
   * Title
   */
  public static final Asn1Oid T = oid("2.5.4.12", "T");

  /**
   * common name - StringType(SIZE(1..64))
   */
  public static final Asn1Oid CN = oid("2.5.4.3", "CN");

  /**
   * street - StringType(SIZE(1..64))
   */
  public static final Asn1Oid STREET = oid("2.5.4.9", "STREET");

  /**
   * device serial number name - StringType(SIZE(1..64))
   */
  public static final Asn1Oid SERIALNUMBER = oid("2.5.4.5", "SERIALNUMBER");

  /**
   * locality name - StringType(SIZE(1..64))
   */
  public static final Asn1Oid L = oid("2.5.4.7", "L");

  /**
   * state, or province name - StringType(SIZE(1..64))
   */
  public static final Asn1Oid ST = oid("2.5.4.8", "ST");

  /**
   * Naming attributes of type X520name
   */
  public static final Asn1Oid SURNAME = oid("2.5.4.4", "surname", "sn");
  public static final Asn1Oid GIVENNAME = oid("2.5.4.42", "GIVENNAME");
  public static final Asn1Oid INITIALS = oid("2.5.4.43", "INITIALS");
  public static final Asn1Oid GENERATION = oid("2.5.4.44", "GENERATION");
  public static final Asn1Oid UNIQUE_IDENTIFIER = oid("2.5.4.45", "UniqueIdentifier");

  public static final Asn1Oid DESCRIPTION = oid("2.5.4.13", "DESCRIPTION");

  /**
   * businessCategory - DirectoryString(SIZE(1..128)
   */
  public static final Asn1Oid BUSINESS_CATEGORY = oid("2.5.4.15",
      "BusinessCategory");

  /**
   * postalCode - DirectoryString(SIZE(1..40)
   */
  public static final Asn1Oid POSTAL_CODE = oid("2.5.4.17", "PostalCode");

  /**
   * dnQualifier - DirectoryString(SIZE(1..64)
   */
  public static final Asn1Oid DN_QUALIFIER = oid("2.5.4.46", "DN",
      "DNQ", "DNQualifier");

  /**
   * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
   */
  public static final Asn1Oid PSEUDONYM = oid("2.5.4.65", "Pseudonym");

  public static final Asn1Oid ROLE = oid("2.5.4.72", "ROLE");

  /**
   * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
   */
  public static final Asn1Oid DATE_OF_BIRTH = oid("1.3.6.1.5.5.7.9.1",
      "DateOfBirth");

  /**
   * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
   */
  public static final Asn1Oid PLACE_OF_BIRTH = oid("1.3.6.1.5.5.7.9.2",
        "PlaceOfBirth");

  /**
   * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
   */
  public static final Asn1Oid GENDER = oid("1.3.6.1.5.5.7.9.3",
          "Gender");

  /**
   * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
   * codes only
   */
  public static final Asn1Oid COUNTRY_OF_CITIZENSHIP = oid("1.3.6.1.5.5.7.9.4",
      "CountryOfCitizenship");

  /**
   * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
   * codes only
   */
  public static final Asn1Oid COUNTRY_OF_RESIDENCE = oid("1.3.6.1.5.5.7.9.4",
        "CountryOfResidence");

  /**
   * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
   */
  public static final Asn1Oid NAME_AT_BIRTH = oid("1.3.36.8.3.14", "NameAtBirth");

  /**
   * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
   * DirectoryString(SIZE(1..30))
   */
  public static final Asn1Oid POSTAL_ADDRESS = oid("2.5.4.16", "PostalAddress");

  /**
   * RFC 2256 dmdName
   */
  public static final Asn1Oid DMD_NAME = oid("2.5.4.54", "DmdName");

  /**
   * id-at-telephoneNumber
   */
  public static final Asn1Oid TELEPHONE_NUMBER = oid(
      X509OIDs.id_at_telephoneNumber.getId(), "TelephoneNumber");

  /**
   * id-at-name
   */
  public static final Asn1Oid NAME = oid(
      X509OIDs.id_at_name.getId(), "Name");

  /**
   * id-at-organizationIdentifier
   */
  public static final Asn1Oid ORGANIZATION_IDENTIFIER = oid(
      X509OIDs.id_at_organizationIdentifier.getId(), "organizationIdentifier");

  /**
   * Email address (RSA PKCS#9 extension) - IA5String.
   */
  public static final Asn1Oid EmailAddress = oid(
      PkcsOIDs.pkcs9_at_emailAddress.getId(), "E", "EmailAddress");

  /**
   * email address
   */
  public static final Asn1Oid E = EmailAddress;

  /**
   * more from PKCS#9
   */
  public static final Asn1Oid UnstructuredName = oid(
      PkcsOIDs.pkcs9_at_unstructuredName.getId(), "UnstructuredName");
  public static final Asn1Oid UnstructuredAddress = oid(
      PkcsOIDs.pkcs9_at_unstructuredAddress.getId(), "UnstructuredAddress");

  /*
  * others...
  */
  public static final Asn1Oid DC = oid("0.9.2342.19200300.100.1.25", "DC");

  /**
   * LDAP User id.
   */
  public static final Asn1Oid UID = oid("0.9.2342.19200300.100.1.1",
      "UID", "userId");

  /**
   * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
   */
  public static final Asn1Oid JURISDICTION_C = oid("1.3.6.1.4.1.311.60.2.1.3",
      "jurisdictionCountry");

  /**
   * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
   */
  public static final Asn1Oid JURISDICTION_ST = oid("1.3.6.1.4.1.311.60.2.1.2",
      "jurisdictionState");

  /**
   * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
   */
  public static final Asn1Oid JURISDICTION_L = oid("1.3.6.1.4.1.311.60.2.1.1",
      "jurisdictionLocality");

  private final List<RDN> rdns;

  private static Asn1Oid oid(String oid, String name, String... aliases) {
    Asn1Oid r = new Asn1Oid(oid);
    nameOidMap.put(r.getId(), r);
    if (name != null) {
      nameOidMap.put(name.toLowerCase(Locale.ROOT), r);
      oidNameMap.put(r.getId(), name);
    }

    if (aliases != null) {
      for (String alias : aliases) {
        nameOidMap.put(alias.toLowerCase(Locale.ROOT), r);
      }
    }

    return r;
  }

  public static X500Name fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static X500Name fromAsn1(Asn1Sequence seq) throws CodecException {
    int count = seq.size();
    RDN[] rdns = new RDN[count];
    for (int i = 0; i < count; i++) {
      rdns[i] = RDN.fromAsn1(seq.getSetAt(i));
    }
    return new X500Name(rdns);
  }

  public X500Name(RDN... rdns) {
    this.rdns = Args.noNullElements2(rdns, "rdns");
  }

  public X500Name(String dirName) {
    String text = Args.notNull(dirName, "dirName").trim();
    if (text.isEmpty()) {
      this.rdns = Collections.emptyList();
      return;
    }

    List<RDN> list = new LinkedList<>();
    AtomicInteger fromIndex = new AtomicInteger(0);

    try {
      do {
        String[] nameValue = nextToken(text, fromIndex);
        String name  = nameValue[0].toLowerCase(Locale.ROOT);
        String value = nameValue[1];

        Asn1Oid type = nameOidMap.get(name);
        if (type == null) {
          try {
            type = new Asn1Oid(name);
          } catch (IllegalArgumentException e) {
          }
        }

        if (type == null) {
          throw new IllegalArgumentException("could not parse attribute name '" + name + "'");
        }

        list.add(new RDN(type, encodeStringValue(type, value).toAsn1Primitive()));
      } while (fromIndex.get() < text.length());
    } catch (RuntimeException | CodecException e) {
      throw new IllegalArgumentException("invalid name '" + text + "'", e);
    }

    this.rdns = list;
  }

  private Asn1Encodable encodeStringValue(Asn1Oid oid, String value)
      throws CodecException {
    if (oid.equals(EmailAddress) || oid.equals(DC)) {
      return new Asn1IA5String(value);
    } else if (oid.equals(DATE_OF_BIRTH)) {
      return new Asn1GeneralizedTime(value);
    } else if (oid.equals(C) || oid.equals(SERIALNUMBER) || oid.equals(DN_QUALIFIER)
        || oid.equals(TELEPHONE_NUMBER) || oid.equals(JURISDICTION_C)) {
      if ((oid.equals(C) || oid.equals(JURISDICTION_C)) && value.length() != 2) {
        throw new IllegalArgumentException("country code attribute "
            + oid.getId() + " must be exactly 2 characters per ISO 3166-1 / X.520, got "
            + value.length() + ": '" + value + "'");
      }
      return new Asn1PrintableString(value);
    } else if (oid.equals(CN) && value.length() > 64) {
      throw new IllegalArgumentException("commonName length "
          + value.length() + " exceeds RFC 5280 ub-common-name (64): '" + value + "'");
    }

    if (!value.isEmpty() && value.charAt(0) == '#') {
      return Asn1Util.readAsn1Object(Hex.decode(value.substring(1)));
    }

    if (!value.isEmpty() && value.charAt(0) == '\\') {
      value = value.substring(1);
    }

    return new Asn1Utf8String(value);
  }

  public List<RDN> getRDNs() {
      return Collections.unmodifiableList(rdns);
  }

  public Set<Asn1Oid> getAttributeTypes() {
    Set<Asn1Oid> oids = new HashSet<>();
    for (RDN rdn : rdns) {
      rdn.collectAttributeTypes(oids);
    }
    return oids;
  }

  public List<RDN> getRDNs(Asn1Oid attributeType) {
    List<RDN> res = new ArrayList<>(1);
    for (RDN rdn : rdns) {
      if (rdn.containsAttributeType(attributeType)) {
        res.add(rdn);
      }
    }

    return res;
  }

  public int size() {
    return rdns.size();
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(rdns);
  }

  private static String[] nextToken(String str, AtomicInteger fromIndex) {
    int strLen = str.length();

    ignoreLeadingChars(str, fromIndex, ' ', ',', '\t');

    // find index of '='
    int equalsIndex = str.indexOf('=', fromIndex.get());
    String name = str.substring(fromIndex.get(), equalsIndex).trim();

    fromIndex.set(equalsIndex + 1);
    ignoreLeadingChars(str, fromIndex, ' ');

    int valueFromIndex = fromIndex.get();
    int valueEndIndex = -1;

    boolean quoted = str.charAt(valueFromIndex) == '"';
    if (quoted) {
      fromIndex.incrementAndGet();
      valueFromIndex++;

      for (int i = fromIndex.get(); i < strLen; i++) {
        if (str.charAt(i) == '"') {
          valueEndIndex = i;
          break;
        }
      }

      if (valueEndIndex == -1) {
        throw new IllegalArgumentException("invalid name '" + str + "'");
      }

      // ignore all letters before the next ","
      fromIndex.set(valueEndIndex + 1);
      for (; fromIndex.get() < strLen; fromIndex.incrementAndGet()) {
        if (str.charAt(fromIndex.get()) == ',') {
          fromIndex.incrementAndGet();
          break;
        }
      }
    } else {
      for (int i = fromIndex.get(); i < strLen; i++) {
        if (str.charAt(i) == ',') {
          valueEndIndex = i;
          break;
        }
      }

      if (valueEndIndex == -1) {
        // last attribute
        valueEndIndex = strLen;
      }

      fromIndex.set(valueEndIndex + 1);
    }

    String value = str.substring(valueFromIndex, valueEndIndex).trim();
    return new String[] {name, value};
  }

  private static void ignoreLeadingChars(String str, AtomicInteger fromIndex, char... chars) {
    // ignore leading spaces
    int strLen = str.length();
    for (int i = fromIndex.get(); i < strLen; i++) {
      char c = str.charAt(i);
      boolean ignore = false;
      for (char c0 : chars) {
        if (c == c0) {
          ignore = true;
          break;
        }
      }

      if (ignore) {
        fromIndex.incrementAndGet();
      } else {
        break;
      }
    }
  }

  @Override
  public int hashCode() {
    return rdns.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof X500Name)) {
      return false;
    }

    X500Name b = (X500Name) obj;
    return rdns.equals(b.rdns);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "");
    int size = rdns.size();
    for (int i = 0; i < size; i++) {
      if (i != 0) {
        buf.append(", ");
      }
      buf.append(rdns.get(i).toString());
    }
    return buf;
  }

  static String getName(Asn1Oid oid) {
    return oidNameMap.get(oid.getId());
  }

}
