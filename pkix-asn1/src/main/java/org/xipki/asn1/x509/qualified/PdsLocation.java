// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * ETSI EN 319 412-5:
 * <pre>
 * esi4-qcStatement-5 QC-STATEMENT ::= {
 *     SYNTAX QcEuPDS IDENTIFIED
 *     BY id-etsi-qcs-QcPDS }
 *
 * QcEuPDS ::= PdsLocations
 *
 * PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation
 *
 * PdsLocation::= SEQUENCE {
 *     url       IA5String,
 *     language  PrintableString (SIZE(2))} --ISO 639-1 language code
 *
 * id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PdsLocation extends Asn1Encodable {

  /**
   * SEQUENCE SIZE (1..MAX) OF PolicyMapping
   */
  public static class Seq1 extends AbstractSeq1<PdsLocation> {

    public Seq1(PdsLocation... entries) {
      super(entries);
    }

    public Seq1(List<PdsLocation> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    @Override
    protected PdsLocation newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return PdsLocation.fromAsn1(coll.getSequenceAt(index));
    }

    public static Seq1 fromEncoded(byte[] encoded) throws CodecException {
      return fromAsn1(Asn1Sequence.fromEncoded(encoded));
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

  }

  private final Asn1IA5String url;

  private final Asn1PrintableString language;

  public PdsLocation(Asn1IA5String url, Asn1PrintableString language) {
    this.url = Args.notNull(url, "url");
    this.language = Args.lengthRange(language, "language", 2, 2);
  }

  public PdsLocation(String url, String language) {
    this(Asn1Util.toIA5String(url), Asn1Util.toPrintableString(language));
  }

  public static PdsLocation fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static PdsLocation fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new PdsLocation(seq.getIA5StringAt(0), seq.getPrintableStringAt(1));
  }

  public Asn1IA5String getUrl() {
    return url;
  }

  public String url() {
    return url.getString();
  }

  public Asn1PrintableString getLanguage() {
    return language;
  }

  public String language() {
    return language.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(url, language);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    url.toStringNoLineSep(buf, indentLevel, "url", true);
    return language.toStringNoLineSep(buf, indentLevel, "language");
  }
}
