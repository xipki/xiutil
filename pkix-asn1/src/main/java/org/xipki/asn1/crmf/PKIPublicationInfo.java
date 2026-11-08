// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.crmf;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * PKIPublicationInfo ::= SEQUENCE {
 *    action     INTEGER {
 *                   dontPublish (0),
 *                   pleasePublish (1) },
 *    pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
 *
 * -- pubInfos MUST NOT be present if action is "dontPublish"
 * -- (if action is "pleasePublish" and pubInfos is omitted,
 * -- "dontCare" is assumed)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKIPublicationInfo extends Asn1Encodable {

  public static final int action_dontPublish = 0;
  public static final int action_pleasePublish = 1;

  private final Asn1Integer action;
  private final SinglePubInfo.Seq1 pubInfos;

  public static PKIPublicationInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Integer action = seq.getNonNegativeIntegerAt(0);
    SinglePubInfo.Seq1 pubInfos = (size == 1) ? null
        : SinglePubInfo.Seq1.fromAsn1(seq.getSequenceAt(1));
    return new PKIPublicationInfo(action, pubInfos);
  }

  private PKIPublicationInfo(Asn1Integer action, SinglePubInfo.Seq1 pubInfos) {
    this.action = action;
    this.pubInfos = pubInfos;
  }

  public PKIPublicationInfo(int action) {
    this.action = new Asn1Integer(action);
    this.pubInfos = null;
  }

  /**
   * Constructor with multiple pubInfo, assumes pleasePublish as the action.
   *
   * @param pubInfos the pubInfos to be published (can be null if don't care is required).
   */
  public PKIPublicationInfo(SinglePubInfo.Seq1 pubInfos) {
    this.action = Asn1Integer.ONE;
    this.pubInfos = pubInfos;
  }

  public Asn1Integer getAction() {
    return action;
  }

  public SinglePubInfo.Seq1 getPubInfos() {
    return pubInfos;
  }

  public int action() {
    return action.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(action, pubInfos);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (action != null) {
      action.toStringNoLineSep(buf, indentLevel, "action", true);
    }

    if (pubInfos != null) {
      pubInfos.toStringWithLineSep(buf, indentLevel, "pubInfos", true);
    }

    return deleteLastNewLine(buf);
  }

}
