// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * Property ::= SEQUENCE {
 *     propertyName  UTF8String (SIZE (1..STRMAX)),
 *     propertyValue UTF8String (SIZE (1..STRMAX)),
 *     status        [0] IMPLICIT AttributeStatus OPTIONAL
 * }
 * </pre>
 * issuerUID is not allowed in this class, since it is forbidden in the v3 certificates.
 *
 * @author Lijun Liao (xipki)
 */
public class Property extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<Property> {

    public Seq1(Property... entries) {
      super(entries);
    }

    public Seq1(List<Property> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected Property newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return Property.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Utf8String propertyName;

  private final Asn1Utf8String propertyValue;

  private final AttributeStatus status;

  public Property(String propertyName, String propertyValue, AttributeStatus status) {
    this(Asn1Util.toUtf8String(propertyName), Asn1Util.toUtf8String(propertyValue), status);
  }

  public Property(Asn1Utf8String propertyName, Asn1Utf8String propertyValue,
                  AttributeStatus status) {
    this.propertyName = Args.lengthRange(propertyName, "propertyName", 1, TcgConstants.STRMAX);
    this.propertyValue = Args.lengthRange(propertyValue, "propertyValue", 1, TcgConstants.STRMAX);
    this.status = status;
  }

  public Asn1Utf8String getPropertyName() {
    return propertyName;
  }

  public Asn1Utf8String getPropertyValue() {
    return propertyValue;
  }

  public AttributeStatus getStatus() {
    return status;
  }

  public String propertyName() {
    return propertyName.getString();
  }

  public String propertyValue() {
    return propertyValue.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(propertyName, propertyValue,
        status == null ? null : Asn1TaggedObject.newImplicit(0, status));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (propertyName != null) {
      propertyName.toStringNoLineSep(buf, indentLevel, "propertyName", true);
    }

    if (propertyValue != null) {
      propertyValue.toStringNoLineSep(buf, indentLevel, "propertyValue", true);
    }

    if (status != null) {
      status.toStringNoLineSep(buf, indentLevel, "status", true);
    }

    return deleteLastNewLine(buf);
  }

  public static Property fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Utf8String name = seq.getUtf8StringAt(0);
    Asn1Utf8String value = seq.getUtf8StringAt(1);

    int index = 2;
    AttributeStatus status = seq.isNotTaggedAt(index, 0) ? null
        : AttributeStatus.fromAsn1(seq.getEnumeratedTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new Property(name, value, status);
  }

}
