// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cert;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Microsoft's CertificateTemplate
 * <pre>
 * CertificateTemplate ::= SEQUENCE {
 *     templateID OBJECT IDENTIFIER,
 *     templateMajorVersion INTEGER OPTIONAL,
 *     templateMinorVersion INTEGER OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class MicrosoftCertificateTemplate extends Asn1Encodable {

  private final Asn1Oid id;

  private final Asn1Integer majorVersion;

  private final Asn1Integer minorVersion;

  public MicrosoftCertificateTemplate(
      Asn1Oid id, Asn1Integer majorVersion, Asn1Integer minorVersion) {
    this.id = Args.notNull(id, "id");
    if (minorVersion != null) {
      Args.notNull(majorVersion, "majorVersion");
    }
    this.majorVersion = majorVersion;
    this.minorVersion = minorVersion;
  }

  public MicrosoftCertificateTemplate(Asn1Oid id, Integer majorVersion, Integer minorVersion) {
    this(id, Asn1Util.toInteger(majorVersion), Asn1Util.toInteger(minorVersion));
  }

  public static MicrosoftCertificateTemplate fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static MicrosoftCertificateTemplate fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 3);
    Asn1Oid id = seq.getOidAt(0);
    Asn1Integer major = null;
    if (size > 1) {
      major = seq.getNonNegativeIntegerAt(1);
    }

    Asn1Integer minor = null;
    if (size > 2) {
      minor = seq.getNonNegativeIntegerAt(2);
    }
    return new MicrosoftCertificateTemplate(id, major, minor);
  }

  public Asn1Oid getId() {
    return id;
  }

  public Asn1Integer getMajorVersion() {
    return majorVersion;
  }

  public Integer majorVersion() {
    return Asn1Util.fromAsn1Int(majorVersion);
  }

  public Asn1Integer getMinorVersion() {
    return minorVersion;
  }

  public Integer minorVersion() {
    return Asn1Util.fromAsn1Int(minorVersion);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(id, majorVersion, minorVersion);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    id.toStringNoLineSep(buf, indentLevel, "templateID", true);
    if (majorVersion != null) {
      majorVersion.toStringNoLineSep(buf, indentLevel, "majorVersion", true);
    }

    if (minorVersion != null) {
      minorVersion.toStringNoLineSep(buf, indentLevel, "minorVersion", true);
    }
    return deleteLastNewLine(buf);
  }
}
