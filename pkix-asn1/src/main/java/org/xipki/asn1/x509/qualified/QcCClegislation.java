// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.PrintableStringSeq;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * ETSI EN 319 412-5:
 * <pre>
 * esi4-qcStatement-7 QC-STATEMENT ::= {
 *     SYNTAX QcCClegislation IDENTIFIED BY
 *     id-etsi-qcs-QcCClegislation }
 *
 * id-etsi-qcs-QcCClegislation OBJECT IDENTIFIER ::= { id-etsi-qcs 7 }
 *
 * QcCClegislation ::= SEQUENCE OF CountryName
 *
 * CountryName ::= PrintableString (SIZE (2)) (
 *   CONSTRAINED BY { -- ISO 3166-1 [6] alpha-2 codes only -- })
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class QcCClegislation extends PrintableStringSeq {

  public QcCClegislation(Asn1PrintableString... entries) {
    super(0, entries);
    validateString();
  }

  public QcCClegislation(List<Asn1PrintableString> entries) {
    super(0, entries);
    validateString();
  }

  public QcCClegislation(String... entries) {
    super(0, entries);
    validateString();
  }

  private QcCClegislation(Asn1Sequence seq) throws CodecException {
    super(0, seq);
    validateString();
  }

  private void validateString() {
    for (Asn1PrintableString entry : entries) {
      String text = entry.getString();
      if (text.length() != 2) {
        throw new IllegalArgumentException("entry is not of size 2: " + text.length());
      }
    }
  }

  public static QcCClegislation fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static QcCClegislation fromAsn1(Asn1Sequence seq) throws CodecException {
    return new QcCClegislation(seq);
  }

}
