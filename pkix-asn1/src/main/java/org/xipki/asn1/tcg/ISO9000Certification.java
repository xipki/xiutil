// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1Boolean;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * <pre>
 * ISO9000Certification ::= SEQUENCE {
 *     iso9000Certified BOOLEAN DEFAULT FALSE,
 *     iso9000Uri       IA5String (SIZE (1..URIMAX)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ISO9000Certification extends Asn1Encodable {

  private final boolean iso9000Certified;

  private final Asn1IA5String iso9000Uri;

  public ISO9000Certification(boolean iso9000Certified, String iso9000Uri) {
    this(iso9000Certified, Asn1Util.toIA5String(iso9000Uri));
  }

  public ISO9000Certification(boolean iso9000Certified, Asn1IA5String iso9000Uri) {
    this.iso9000Certified = iso9000Certified;
    this.iso9000Uri = Args.lengthRange(iso9000Uri, "iso9000Uri", 1, TcgConstants.URIMAX);
  }

  public boolean isIso9000Certified() {
    return iso9000Certified;
  }

  public Asn1IA5String getIso9000Uri() {
    return iso9000Uri;
  }

  public String iso9000Uri() {
    return Asn1Util.fromAsn1(iso9000Uri);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(iso9000Certified ? Asn1Boolean.TRUE :null,
        iso9000Uri);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "iso9000Certified: " + iso9000Certified + "\n");

    if (iso9000Uri != null) {
      iso9000Uri.toStringNoLineSep(buf, indentLevel, "iso9000Uri", true);
    }

    return deleteLastNewLine(buf);
  }

  public static ISO9000Certification fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ISO9000Certification fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 2);
    int index = 0;
    boolean certified = seq.hasBoolean(index) && seq.getBooleanAt(index++).isTrue();
    Asn1IA5String uri = seq.notHasIA5String(index) ? null : seq.getIA5StringAt(index++);
    Asn1Util.checkSequenceEnd(index, size);
    return new ISO9000Certification(certified, uri);
  }

}
