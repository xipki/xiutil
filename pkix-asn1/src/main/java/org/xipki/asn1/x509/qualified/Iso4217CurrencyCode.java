// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;

import java.math.BigInteger;

/**
 * The Iso4217CurrencyCode object.
 * <pre>
 * Iso4217CurrencyCode  ::=  CHOICE {
 *     alphabetic  PrintableString (SIZE 3), --Recommended
 *     numeric     INTEGER (1..999) }
 * -- Alphabetic or numeric currency code as defined in ISO 4217
 * -- It is recommended that the Alphabetic form is used
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Iso4217CurrencyCode extends Asn1Encodable {

  private final Asn1PrintableString alphabetic;
  private final Asn1Integer numeric;

  public static Iso4217CurrencyCode fromAsn1(Asn1Primitive obj) {
    Args.notNull(obj, "obj");

    if (obj instanceof Asn1Integer) {
      Asn1Integer numeric = (Asn1Integer) obj;
      // CurrencyCode ::= INTEGER (1..999)
      BigInteger value = numeric.getValue();
      if (value.signum() != 1 || value.compareTo(BigInteger.valueOf(999)) > 0) {
        throw new IllegalArgumentException("invalid numeric currency code " + value);
      }
      return Iso4217CurrencyCode.ofNumeric(numeric);
    } else if (obj instanceof Asn1PrintableString) {
      return Iso4217CurrencyCode.ofAlphabetic((Asn1PrintableString) obj);
    } else {
      throw new IllegalArgumentException("unknown object in getInstance");
    }
  }

  private Iso4217CurrencyCode(Asn1PrintableString alphabetic, Asn1Integer numeric) {
    this.alphabetic = alphabetic;
    this.numeric = numeric;
  }

  public static Iso4217CurrencyCode ofNumeric(int numeric) {
    Args.range(numeric, "numeric", 1, 999);
    return new Iso4217CurrencyCode(null, new Asn1Integer(numeric));
  }

  public static Iso4217CurrencyCode ofNumeric(Asn1Integer numeric) {
    return new Iso4217CurrencyCode(null, Args.notNull(numeric, "numeric"));
  }

  public static Iso4217CurrencyCode ofAlphabetic(String alphabetic) {
    Args.lengthRange(alphabetic, "alphabetic", 3, 3);
    return new Iso4217CurrencyCode(new Asn1PrintableString(alphabetic), null);
  }

  public static Iso4217CurrencyCode ofAlphabetic(Asn1PrintableString alphabetic) {
    Args.notNull(alphabetic, "alphabetic");
    Args.lengthRange(alphabetic.getString(), "alphabetic", 3, 3);
    return new Iso4217CurrencyCode(alphabetic, null);
  }

  public boolean isAlphabetic() {
    return alphabetic != null;
  }

  public Asn1PrintableString getAlphabetic() {
    return alphabetic;
  }

  public Asn1Integer getNumeric() {
    return numeric;
  }

  public String alphabetic() {
    return Asn1Util.fromAsn1(alphabetic);
  }

  public Integer numeric() {
    return Asn1Util.fromAsn1Int(numeric);
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return numeric != null ? numeric : alphabetic;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return (alphabetic != null) ? alphabetic.toString(buf, indentLevel)
        : numeric.toString(buf, indentLevel);
  }

}
