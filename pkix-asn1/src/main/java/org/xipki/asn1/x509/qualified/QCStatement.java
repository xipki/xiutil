// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractCollection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.QCStatementOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * The QCStatement object.
 * <pre>
 * QCStatement ::= SEQUENCE {
 *   statementId        OBJECT IDENTIFIER,
 *   statementInfo      ANY DEFINED BY statementId OPTIONAL}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class QCStatement extends Asn1Encodable {

  /**
   * SEQUENCE OF QCStatement
   */
  public static class Seq0 extends AbstractSeq0<QCStatement> {

    public Seq0(QCStatement... entries) {
      super(entries);
    }

    public Seq0(List<QCStatement> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected QCStatement newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return QCStatement.fromAsn1(coll.getSequenceAt(index));
    }

  }

  private final Asn1Oid statementId;
  private final Asn1Primitive statementInfo;

  private boolean parsed;

  private MonetaryValue qcLimitValue;

  private Asn1Integer qcEuRetentionPeriod;

  private PdsLocations qcPDS;

  private QcType qcType;

  private QcCClegislation qcCClegislation;

  public static QCStatement fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static QCStatement fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);

    // qcStatementId
    Asn1Oid qcStatementId = seq.getOidAt(0);
    Asn1Primitive qcStatementInfo = (size == 1) ? null : seq.getObjectAt(1);
    QCStatement r = new QCStatement(qcStatementId, qcStatementInfo);
    r.parseValue();
    return r;
  }

  public static QCStatement createNoParse(Asn1Oid qcStatementId, Asn1Encodable qcStatementInfo) {
    Asn1Primitive p = qcStatementInfo == null ? null : qcStatementInfo.toAsn1Primitive();
    return new QCStatement(qcStatementId, p);
  }

  public static QCStatement create(Asn1Oid qcStatementId) {
    QCStatement r = createNoParse(qcStatementId, null);
    r.parsed = true;
    return r;
  }

  public static QCStatement create(Asn1Oid qcStatementId, Asn1Encodable qcStatementInfo)
      throws CodecException {
    QCStatement r = createNoParse(qcStatementId, qcStatementInfo);
    r.parseValue();
    return r;
  }

  private static QCStatement create2(Asn1Oid qcStatementId, Asn1Encodable qcStatementInfo) {
    QCStatement r = createNoParse(qcStatementId, qcStatementInfo);
    r.parsed = true;
    return r;
  }

  private QCStatement(Asn1Oid statementId, Asn1Primitive statementInfo) {
    this.statementId = Args.notNull(statementId, "statementId");
    this.statementInfo = statementInfo;
  }

  public static QCStatement ofQcCompliance() {
    return create2(QCStatementOIDs.id_etsi_qcs_QcCompliance, null);
  }

  public static QCStatement ofQcLimitValue(MonetaryValue value) {
    Args.notNull(value, "value");
    QCStatement r = create2(QCStatementOIDs.id_etsi_qcs_QcLimitValue, value);
    r.qcLimitValue = value;
    return r;
  }

  public static QCStatement ofQcRetentionPeriod(BigInteger value) {
    return ofQcRetentionPeriod(Asn1Util.toInteger(value));
  }

  public static QCStatement ofQcRetentionPeriod(Asn1Integer value) {
    Args.notNull(value, "value");
    QCStatement r = create2(QCStatementOIDs.id_etsi_qcs_QcRetentionPeriod, value);
    r.qcEuRetentionPeriod = value;
    return r;
  }

  public static QCStatement ofQcSSCD() {
    return create2(QCStatementOIDs.id_etsi_qcs_QcSSCD, null);
  }

  public static QCStatement ofQcPDS(PdsLocations value) {
    Args.notNull(value, "value");
    QCStatement r = create2(QCStatementOIDs.id_etsi_qcs_QcPDS, value);
    r.qcPDS = value;
    return r;
  }

  public static QCStatement ofQcType(QcType value) {
    Args.notNull(value, "value");
    QCStatement r = create2(QCStatementOIDs.id_etsi_qcs_QcType, value);
    r.qcType = value;
    return r;
  }

  public static QCStatement ofQcCClegislation(QcCClegislation value) {
    Args.notNull(value, "value");
    QCStatement r = create2(QCStatementOIDs.id_etsi_qcs_QcCClegislation, value);
    r.qcCClegislation = value;
    return r;
  }

  public Asn1Oid getStatementId() {
    return statementId;
  }

  public Asn1Primitive getStatementInfo() {
    return statementInfo;
  }

  public MonetaryValue getQcLimitValue() {
    return qcLimitValue;
  }

  public Asn1Integer getQcEuRetentionPeriod() {
    return qcEuRetentionPeriod;
  }

  public BigInteger qcEuRetentionPeriod() {
    return Asn1Util.fromAsn1(qcEuRetentionPeriod);
  }

  public PdsLocations getQcPDS() {
    return qcPDS;
  }

  public QcType getQcType() {
    return qcType;
  }

  public QcCClegislation getQcCClegislation() {
    return qcCClegislation;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(statementId, statementInfo);
  }

  private void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    String id = statementId.getId();
    if (id.equals(QCStatementOIDs.id_etsi_qcs_QcCompliance.getId())) {
      // statementInfo is null
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcLimitValue.getId())) {
      qcLimitValue = MonetaryValue.fromAsn1(statementInfo.asSequence());
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcRetentionPeriod.getId())) {
      qcEuRetentionPeriod = Asn1Integer.checkNonNegative(statementInfo.asInteger());
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcSSCD.getId())) {
      // statementInfo is null
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcPDS.getId())) {
      qcPDS = PdsLocations.fromAsn1(statementInfo.asSequence());
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcType.getId())) {
      qcType = QcType.fromAsn1(statementInfo.asSequence());
    } else if (id.equals(QCStatementOIDs.id_etsi_qcs_QcCClegislation.getId())) {
      qcCClegislation = QcCClegislation.fromAsn1(statementInfo.asSequence());
    }

    parsed = true;
  }

  private Asn1Encodable parsedValue() {
    if (!parsed) {
      return statementInfo;
    }

    if (qcLimitValue != null) {
      return qcLimitValue;
    } else if (qcEuRetentionPeriod != null) {
      return qcEuRetentionPeriod;
    } else if (qcPDS != null) {
      return qcPDS;
    } else if (qcType != null) {
      return qcType;
    } else if (qcCClegislation != null) {
      return qcCClegislation;
    }

    return statementInfo;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    statementId.toStringNoLineSep(buf, indentLevel, "statementId", true);

    Asn1Encodable parsedValue = parsedValue();
    if (parsedValue instanceof AbstractCollection) {
      parsedValue.toStringWithLineSep(buf, indentLevel, "statementInfo", true);
    } else if (parsedValue != null) {
      parsedValue.toStringWithLineSep(buf, indentLevel, "statementInfo", true);
    }
    return deleteLastNewLine(buf);
  }
}
