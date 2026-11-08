// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * The MonetaryValue object.
 * <pre>
 * MonetaryValue  ::=  SEQUENCE {
 *    currency  Iso4217CurrencyCode,
 *    amount    INTEGER,
 *    exponent  INTEGER }
 * -- value = amount * 10^exponent
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class MonetaryValue extends Asn1Encodable {

  private final Iso4217CurrencyCode currency;
  private final Asn1Integer amount;
  private final Asn1Integer exponent;

  public static MonetaryValue fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    Iso4217CurrencyCode currency = Iso4217CurrencyCode.fromAsn1(seq.getObjectAt(0));
    Asn1Integer amount = seq.getIntegerAt(1);
    Asn1Integer exponent = seq.getIntegerAt(2);
    return new MonetaryValue(currency, amount, exponent);
  }

  public MonetaryValue(Iso4217CurrencyCode currency, int amount, int exponent) {
    this.currency = Args.notNull(currency, "currency");
    this.amount = new Asn1Integer(amount);
    this.exponent = new Asn1Integer(exponent);
  }

  public MonetaryValue(Iso4217CurrencyCode currency, Asn1Integer amount, Asn1Integer exponent) {
    this.currency = Args.notNull(currency, "currency");
    this.amount = Args.notNull(amount, "amount");
    this.exponent = Args.notNull(exponent, "exponent");
  }

  public Iso4217CurrencyCode getCurrency() {
    return currency;
  }

  public Asn1Integer getAmount() {
    return amount;
  }

  public Asn1Integer getExponent() {
    return exponent;
  }

  public int amount() {
    return amount.intValueExact();
  }

  public int exponent() {
    return exponent.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(currency, amount, exponent);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    currency.toStringNoLineSep(buf, indentLevel, "currency", true);
    amount.toStringNoLineSep(buf, indentLevel, "amount", true);
    return exponent.toStringNoLineSep(buf, indentLevel, "exponent");
  }
}
