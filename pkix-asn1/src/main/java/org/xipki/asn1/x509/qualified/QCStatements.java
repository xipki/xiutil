// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509.qualified;

import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * QCStatements ::= SEQUENCE OF QCStatement
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class QCStatements extends QCStatement.Seq0 {

  public QCStatements(QCStatement... entries) {
    super(entries);
  }

  public QCStatements(List<QCStatement> entries) {
    super(entries);
  }

  protected QCStatements(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static QCStatements fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static QCStatements fromAsn1(Asn1Sequence seq) throws CodecException {
    return new QCStatements(seq);
  }

}
