// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * entityGeoLocationTrait TRAIT ::= {
 *     SYNTAX EntityGeoLocation
 *     IDENTIFIED BY tcg-tr-ID-entGeoLocation
 * }
 *
 * ISO3166CountryCode ::= PrintableString (SIZE(2..3))
 *
 * ISO3166AdminSubdivisionCode ::= PrintableString (SIZE (3..6))
 *
 * OpenLocationCode ::= PrintableString
 *
 * EntityGeoLocation ::= SEQUENCE {
 *     countryCode     ISO3166CountryCode,
 *     stateOrProvince [0] IMPLICIT ISO3166AdminSubdivisionCode OPTIONAL,
 *     localityName    [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     streetAddress   [2] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     locationCoords  [3] IMPLICIT OpenLocationCode OPTIONAL,
 *     postalCode      [5] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EntityGeoLocation extends Asn1Encodable {

  private final Asn1PrintableString countryCode;

  private final Asn1PrintableString stateOrProvince;

  private final Asn1Utf8String localityName;

  private final Asn1Utf8String streetAddress;

  private final Asn1PrintableString locationCoords;

  private final Asn1Utf8String postalCode;

  private EntityGeoLocation(Asn1PrintableString countryCode, Asn1PrintableString stateOrProvince,
                            Asn1Utf8String localityName, Asn1Utf8String streetAddress,
                            Asn1PrintableString locationCoords, Asn1Utf8String postalCode) {
    this.countryCode = countryCode;
    this.stateOrProvince = stateOrProvince;
    this.localityName = localityName;
    this.streetAddress = streetAddress;
    this.locationCoords = locationCoords;
    this.postalCode = postalCode;
  }

  public EntityGeoLocation(String countryCode, String stateOrProvince,
                           String localityName, String streetAddress,
                           String locationCoords, String postalCode) {
    this.countryCode = new Asn1PrintableString(
        Args.lengthRange(countryCode, "countryCode", 2, 3));

    if (stateOrProvince != null) {
      Args.lengthRange(stateOrProvince, "stateOrProvince", 3, 6);
    }
    this.stateOrProvince = (stateOrProvince == null) ? null
        : new Asn1PrintableString(stateOrProvince);

    if (localityName != null) {
      Args.lengthRange(localityName, "localityName", 1, TcgConstants.STRMAX);
    }
    this.localityName = (localityName == null) ? null : new Asn1Utf8String(localityName);

    if (streetAddress != null) {
      Args.lengthRange(streetAddress, "streetAddress", 1, TcgConstants.STRMAX);
    }
    this.streetAddress = (streetAddress == null) ? null : new Asn1Utf8String(streetAddress);

    if (locationCoords != null) {
      Args.lengthRange(locationCoords, "locationCoords", 3, 6);
    }
    this.locationCoords = (locationCoords == null) ? null : new Asn1PrintableString(locationCoords);

    if (postalCode != null) {
      Args.lengthRange(postalCode, "postalCode", 1, TcgConstants.STRMAX);
    }
    this.postalCode = (postalCode == null) ? null : new Asn1Utf8String(postalCode);
  }

  public Asn1PrintableString getCountryCode() {
    return countryCode;
  }

  public Asn1PrintableString getStateOrProvince() {
    return stateOrProvince;
  }

  public Asn1Utf8String getLocalityName() {
    return localityName;
  }

  public Asn1Utf8String getStreetAddress() {
    return streetAddress;
  }

  public Asn1PrintableString getLocationCoords() {
    return locationCoords;
  }

  public Asn1Utf8String getPostalCode() {
    return postalCode;
  }

  public String countryCode() {
    return countryCode.getString();
  }

  public String stateOrProvince() {
    return Asn1Util.fromAsn1(stateOrProvince);
  }

  public String localityName() {
    return Asn1Util.fromAsn1(localityName);
  }

  public String streetAddress() {
    return Asn1Util.fromAsn1(streetAddress);
  }

  public String locationCoords() {
    return Asn1Util.fromAsn1(locationCoords);
  }

  public String postalCode() {
    return Asn1Util.fromAsn1(postalCode);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(countryCode,
        stateOrProvince == null ? null : Asn1TaggedObject.newImplicit(0, stateOrProvince),
        localityName    == null ? null : Asn1TaggedObject.newImplicit(1, localityName),
        streetAddress   == null ? null : Asn1TaggedObject.newImplicit(2, streetAddress),
        locationCoords  == null ? null : Asn1TaggedObject.newImplicit(3, locationCoords),
        postalCode      == null ? null : Asn1TaggedObject.newImplicit(5, postalCode)
    );
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (countryCode != null) {
      countryCode.toStringNoLineSep(buf, indentLevel, "countryCode", true);
    }

    if (stateOrProvince != null) {
      stateOrProvince.toStringNoLineSep(buf, indentLevel, "stateOrProvince", true);
    }

    if (localityName != null) {
      localityName.toStringNoLineSep(buf, indentLevel, "localityName", true);
    }

    if (streetAddress != null) {
      streetAddress.toStringNoLineSep(buf, indentLevel, "streetAddress", true);
    }

    if (locationCoords != null) {
      locationCoords.toStringNoLineSep(buf, indentLevel, "locationCoords", true);
    }

    if (postalCode != null) {
      postalCode.toStringNoLineSep(buf, indentLevel, "postalCode", true);
    }

    return deleteLastNewLine(buf);
  }

  public static EntityGeoLocation fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 6);
    Asn1PrintableString countryCode = seq.getPrintableStringAt(0);

    int index = 1;
    Asn1PrintableString stateOrProvince = seq.isNotTaggedAt(index, 0) ? null
        : seq.getPrintableStringTaggedAt(index++, false);

    Asn1Utf8String localityName = seq.isNotTaggedAt(index, 1) ? null
        : seq.getUtf8StringTaggedAt(index++, false);

    Asn1Utf8String streetAddress = seq.isNotTaggedAt(index, 2) ? null
        : seq.getUtf8StringTaggedAt(index++, false);

    Asn1PrintableString locationCoords = seq.isNotTaggedAt(index, 3) ? null
        : seq.getPrintableStringTaggedAt(index++, false);

    Asn1Utf8String postalCode = seq.isNotTaggedAt(index, 5) ? null
        : seq.getUtf8StringTaggedAt(index++, false);

    Asn1Util.checkSequenceEnd(index, size);
    return new EntityGeoLocation(countryCode, stateOrProvince, localityName,
        streetAddress, locationCoords, postalCode);
  }

}
