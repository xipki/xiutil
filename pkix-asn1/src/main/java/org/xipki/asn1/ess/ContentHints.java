// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ess;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * ContentHints ::= SEQUENCE {
 *   contentDescription  UTF8String (SIZE (1..MAX)) OPTIONAL,
 *   contentType         ContentType }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ContentHints extends Asn1Encodable {

  private final Asn1Utf8String contentDescription;
  private final Asn1Oid contentType;

  public static ContentHints fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Utf8String contentDescription = (size == 1) ? null : seq.getUtf8StringAt(0);
    Asn1Oid contentType = seq.getOidAt(size - 1);
    return new ContentHints(contentType, contentDescription);
  }

  public ContentHints(Asn1Oid contentType) {
    this(contentType, null);
  }

  public ContentHints(Asn1Oid contentType, Asn1Utf8String contentDescription) {
    this.contentType = Args.notNull(contentType, "contentType");
    this.contentDescription = contentDescription;
  }

  public Asn1Oid getContentType() {
    return contentType;
  }

  public Asn1Utf8String getContentDescription() {
    return contentDescription;
  }

  public String contentDescription() {
    return Asn1Util.fromAsn1(contentDescription);
  }

  @Override
  public Asn1Primitive toAsn1Primitive()   {
    return Asn1Sequence.buildIgnoreNull(contentDescription, contentType);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (contentDescription != null) {
      contentDescription.toStringNoLineSep(buf, indentLevel, "contentDescription", true);
    }

    contentType.toStringNoLineSep(buf, indentLevel, "contentType", true);

    return deleteLastNewLine(buf);
  }

}
