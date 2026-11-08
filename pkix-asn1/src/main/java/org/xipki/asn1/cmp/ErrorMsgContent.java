// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * <pre>
 *      ErrorMsgContent ::= SEQUENCE {
 *          pKIStatusInfo          PKIStatusInfo,
 *          errorCode              INTEGER           OPTIONAL,
 *          -- implementation-specific error codes
 *          errorDetails           PKIFreeText       OPTIONAL
 *          -- implementation-specific error details
 *      }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ErrorMsgContent extends Asn1Encodable {

  private final PKIStatusInfo pkiStatusInfo;
  private final Asn1Integer errorCode;
  private final PKIFreeText errorDetails;

  public static ErrorMsgContent fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    PKIStatusInfo pkiStatusInfo = PKIStatusInfo.fromAsn1(seq.getSequenceAt(0));

    int index = 1;
    Asn1Integer errorCode = seq.notHasInteger(index) ? null : seq.getIntegerAt(index++);
    PKIFreeText errorDetails = seq.notHasSequence(index) ? null
        : PKIFreeText.fromAsn1(seq.getSequenceAt(index++));
    Asn1Util.checkSequenceEnd(index, size);
    return new ErrorMsgContent(pkiStatusInfo, errorCode, errorDetails);
  }

  public ErrorMsgContent(PKIStatusInfo pkiStatusInfo) {
    this(pkiStatusInfo, null, null);
  }

  public ErrorMsgContent(PKIStatusInfo pkiStatusInfo, Asn1Integer errorCode,
                         PKIFreeText errorDetails) {
      this.pkiStatusInfo = Args.notNull(pkiStatusInfo, "pkiStatusInfo");
      this.errorCode = errorCode;
      this.errorDetails = errorDetails;
  }

  public PKIStatusInfo getPkiStatusInfo() {
    return pkiStatusInfo;
  }

  public Asn1Integer getErrorCode() {
    return errorCode;
  }

  public PKIFreeText getErrorDetails() {
    return errorDetails;
  }

  public BigInteger errorCode() {
    return Asn1Util.fromAsn1(errorCode);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(pkiStatusInfo, errorCode, errorDetails);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    pkiStatusInfo.toStringWithLineSep(buf, indentLevel, "pkiStatusInfo", true);

    if (errorCode != null) {
      errorCode.toStringNoLineSep(buf, indentLevel, "errorCode", true);
    }

    if (errorDetails != null) {
      errorDetails.toStringWithLineSep(buf, indentLevel, "errorDetails", true);
    }

    return deleteLastNewLine(buf);
  }
}
