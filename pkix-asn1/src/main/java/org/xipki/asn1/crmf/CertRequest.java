// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.asn1.cmp.Controls;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * <pre>
 * CertRequest ::= SEQUENCE {
 *     certReqId     INTEGER,       -- ID for matching request and reply
 *     certTemplate  CertTemplate,  -- Selected fields of cert to be issued
 *     controls      Controls OPTIONAL }   -- Attributes affecting issuance
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertRequest extends Asn1Encodable {

  private final Asn1Integer certReqId;
  private final CertTemplate certTemplate;
  private final Controls controls;

  public static CertRequest fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer certReqId = seq.getIntegerAt(0);
    CertTemplate certTemplate = CertTemplate.fromAsn1(seq.getSequenceAt(1));
    Controls controls = size == 2 ? null : Controls.fromAsn1(seq.getSequenceAt(2));
    return new CertRequest(certReqId, certTemplate, controls);
  }

  public CertRequest(int certReqId, CertTemplate certTemplate, Controls controls) {
    this(new Asn1Integer(certReqId), certTemplate, controls);
  }

  public CertRequest(Asn1Integer certReqId, CertTemplate certTemplate, Controls controls) {
    this.certReqId = Args.notNull(certReqId, "certReqId");
    this.certTemplate = Args.notNull(certTemplate, "certTemplate");
    this.controls = controls;
  }

  public Asn1Integer getCertReqId() {
    return certReqId;
  }

  public CertTemplate getCertTemplate() {
    return certTemplate;
  }

  public Controls getControls() {
    return controls;
  }

  public BigInteger certReqId() {
    return certReqId.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(certReqId, certTemplate, controls);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    certReqId.toStringNoLineSep(buf, indentLevel, "certReqId", true);
    certTemplate.toStringWithLineSep(buf, indentLevel, "certTemplate", true);

    if (controls != null) {
      controls.toStringWithLineSep(buf, indentLevel, "controls", true);
    }

    return deleteLastNewLine(buf);
  }
}
