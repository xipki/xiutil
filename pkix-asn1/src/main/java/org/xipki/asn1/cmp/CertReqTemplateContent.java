// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertTemplate;
import org.xipki.asn1.x500.AttributeTypeAndValue;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * GenMsg:    {id-it 19}, &lt; absent &gt;
 * GenRep:    {id-it 19}, CertReqTemplateContent | &lt; absent &gt;
 * <p>
 * CertReqTemplateValue  ::= CertReqTemplateContent
 * <p>
 * CertReqTemplateContent ::= SEQUENCE {
 *     certTemplate  CertTemplate,
 *     keySpec       Controls OPTIONAL }
 * <p>
 * Controls  ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
 *
 * @author Lijun Liao (xipki)
 */
public class CertReqTemplateContent extends Asn1Encodable {

  private final CertTemplate certTemplate;
  private final Controls keySpec;

  public static CertReqTemplateContent fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static CertReqTemplateContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    CertTemplate certTemplate = CertTemplate.fromAsn1(seq.getSequenceAt(0));
    Controls keySpec = (size == 1) ? null : Controls.fromAsn1(seq.getSequenceAt(1));
    return new CertReqTemplateContent(certTemplate, keySpec);
  }

  public CertReqTemplateContent(CertTemplate certTemplate, Controls keySpec) {
    this.certTemplate = Args.notNull(certTemplate, "certTemplate");
    this.keySpec = keySpec;
  }

  public CertTemplate getCertTemplate() {
    return certTemplate;
  }

  public AttributeTypeAndValue.Seq1 getKeySpec() {
    return keySpec;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certTemplate, keySpec);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certTemplate.toStringWithLineSep(buf, indentLevel, "certTemplate", true);

    if (keySpec != null) {
      keySpec.toStringWithLineSep(buf, indentLevel, "keySpec", true);
    }

    return deleteLastNewLine(buf);
  }

}
