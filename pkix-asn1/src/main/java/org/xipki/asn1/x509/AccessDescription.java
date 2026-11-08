// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The AccessDescription object.
 * <pre>
 * AccessDescription  ::=  SEQUENCE {
 *     accessMethod          OBJECT IDENTIFIER,
 *     accessLocation        GeneralName  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AccessDescription extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq0<AccessDescription> {

    public Seq1(AccessDescription... entries) {
      super(entries);
    }

    public Seq1(List<AccessDescription> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected AccessDescription newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AccessDescription.fromAsn1(coll.getSequenceAt(index));
    }

  }

  public final static Asn1Oid id_ad_caIssuers = new Asn1Oid("1.3.6.1.5.5.7.48.2");

  public final static Asn1Oid id_ad_ocsp = new Asn1Oid("1.3.6.1.5.5.7.48.1");

  private final Asn1Oid accessMethod;
  private final GeneralName accessLocation;

  public static AccessDescription fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid accessMethod = seq.getOidAt(0);
    GeneralName accessLocation = GeneralName.fromAsn1(seq.getTaggedAt(1));
    return new AccessDescription(accessMethod, accessLocation);
  }

  public AccessDescription(Asn1Oid accessMethod, GeneralName accessLocation) {
    this.accessMethod = Args.notNull(accessMethod, "accessMethod");
    this.accessLocation = Args.notNull(accessLocation, "accessLocation");
  }

  public Asn1Oid getAccessMethod() {
    return accessMethod;
  }

  public GeneralName getAccessLocation() {
    return accessLocation;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(accessMethod, accessLocation);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    accessMethod.toStringNoLineSep(buf, indentLevel, "accessMethod", true);
    return accessLocation.toStringWithLineSep(buf, indentLevel, "accessLocation");
  }
}
