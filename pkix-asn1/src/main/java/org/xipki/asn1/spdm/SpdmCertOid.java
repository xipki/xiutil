// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.spdm;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.oid.SpdmOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.1.pdf
 *
 * <pre>
 * id-spdm-cert-oid ::= SEQUENCE {
 *    spdmOID           OBJECT IDENTIFIER,
 *    spdmOIDdefinition OCTET STRING OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SpdmCertOid extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<SpdmCertOid> {

    public Seq1(SpdmCertOid... entries) {
      super(entries);
    }

    public Seq1(List<SpdmCertOid> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected SpdmCertOid newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return SpdmCertOid.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid spdmOID;

  private final Asn1OctetString spdmOIDdefinition;

  public static SpdmCertOid fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid oid = seq.getOidAt(0);
    Asn1OctetString definition = size == 1 ? null : seq.getOctetStringAt(1);
    return new SpdmCertOid(oid, definition);
  }

  private SpdmCertOid(Asn1Oid spdmOID, Asn1OctetString spdmOIDdefinition) {
    this.spdmOID = Args.notNull(spdmOID, "spdmOID");
    if (spdmOID.equals(SpdmOIDs.id_DMTF_hardware_identity)
        || spdmOID.equals(SpdmOIDs.id_DMTF_mutable_certificate)) {
      if (spdmOIDdefinition != null) {
        throw new IllegalArgumentException("spdmOIDdefinition shall not be non-null");
      }
    }

    this.spdmOIDdefinition = spdmOIDdefinition;
  }

  public SpdmCertOid(Asn1Oid spdmOID) {
    this(spdmOID, (Asn1OctetString) null);
  }

  public SpdmCertOid(Asn1Oid spdmOID, byte[] spdmOIDdefinition) {
    this(spdmOID, spdmOIDdefinition == null ? null : new Asn1OctetString(spdmOIDdefinition));
  }

  public Asn1Oid getSpdmOID() {
    return spdmOID;
  }

  public Asn1OctetString getSpdmOIDdefinition() {
    return spdmOIDdefinition;
  }

  public byte[] spdmOIDdefinition() {
    return Asn1Util.fromAsn1(spdmOIDdefinition);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(spdmOID, spdmOIDdefinition);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    spdmOID.toStringNoLineSep(buf, indentLevel, "spdmOID");
    if (spdmOIDdefinition != null) {
      buf.append("\n");
      spdmOIDdefinition.toStringWithLineSep(buf, indentLevel, "spdmOIDdefinition");
    }
    return buf;
  }

}
