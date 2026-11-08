// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cms;

import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-8">RFC 5652</a> EncryptedData object.
 * <p>
 * <pre>
 * EncryptedData ::= SEQUENCE {
 *     version                  CMSVersion,
 *     encryptedContentInfo     EncryptedContentInfo,
 *     unprotectedAttrs     [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptedData extends Asn1Encodable {

  private final Asn1Integer version;
  private final EncryptedContentInfo encryptedContentInfo;
  private final Attributes unprotectedAttrs;

  public EncryptedData(EncryptedContentInfo encInfo) {
    this(Asn1Integer.ZERO, encInfo,  null);
  }

  public EncryptedData(EncryptedContentInfo encInfo, Attributes unprotectedAttrs) {
    this((unprotectedAttrs == null ? Asn1Integer.ZERO : Asn1Integer.TWO),
        encInfo, unprotectedAttrs);
  }

  public EncryptedData(Asn1Integer version, EncryptedContentInfo encInfo,
                       Attributes unprotectedAttrs) {
    this.version = Args.notNull(version, "version");
    this.encryptedContentInfo = Args.notNull(encInfo, "encInfo");
    this.unprotectedAttrs = unprotectedAttrs;
  }

  public static EncryptedData fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    EncryptedContentInfo encryptedContentInfo =
        EncryptedContentInfo.fromAsn1(seq.getSequenceAt(1));
    int index = 2;
    Attributes unprotectedAttrs = seq.isNotTaggedAt(index, 1) ? null
        : Attributes.fromAsn1(seq.getSetTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size);
    return new EncryptedData(version, encryptedContentInfo, unprotectedAttrs);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public EncryptedContentInfo getEncryptedContentInfo() {
    return encryptedContentInfo;
  }

  public Attribute.Set1 getUnprotectedAttrs() {
    return unprotectedAttrs;
  }

  public int version() {
    return version.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, encryptedContentInfo,
        (unprotectedAttrs == null ? null : Asn1TaggedObject.newImplicit(1, unprotectedAttrs)));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    encryptedContentInfo.toStringWithLineSep(buf, indentLevel, "encryptedContentInfo", true);

    if (unprotectedAttrs != null) {
      unprotectedAttrs.toStringWithLineSep(buf, indentLevel, "unprotectedAttrs", true);
    }

    return deleteLastNewLine(buf);
  }
}
