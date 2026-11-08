// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 5652:
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType      ContentType,
 *     content      [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ContentInfo extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<ContentInfo> {

    public Seq0(ContentInfo... entries) {
      super(entries);
    }

    public Seq0(List<ContentInfo> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected ContentInfo newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return ContentInfo.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid contentType;
  private final Asn1Primitive content;

  public static ContentInfo build(Asn1Oid contentType, Asn1Encodable content) {
    return new ContentInfo(contentType, content.toAsn1Primitive());
  }

  public static ContentInfo fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ContentInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid contentType = seq.getOidAt(0);
    Asn1Primitive content = null;
    if (size > 1) {
      Asn1TaggedObject tObj = seq.getTaggedAt(1, 0);
      content = tObj.getExplicitBase();
    }
    return new ContentInfo(contentType, content);
  }

  public ContentInfo(Asn1Oid contentType, Asn1Primitive content) {
    this.contentType = Args.notNull(contentType, "contentType");
    this.content = content;
  }

  public Asn1Oid getContentType() {
    return contentType;
  }

  public Asn1Primitive getContent() {
    return content;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(contentType,
        (content == null) ? null : Asn1TaggedObject.newExplicit(0, content));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    contentType.toStringNoLineSep(buf, indentLevel, "contentType", true);

    if (content != null) {
      content.toStringWithLineSep(buf, indentLevel, "content", true);
    }

    return deleteLastNewLine(buf);
  }

}
