// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.smime;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq0;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * SMIMECapability ::= SEQUENCE {
 *     capabilityID OBJECT IDENTIFIER,
 *     parameters ANY DEFINED BY capabilityID OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SMIMECapability extends Asn1Encodable {

  public static class Seq0 extends AbstractSeq0<SMIMECapability> {

    public Seq0(SMIMECapability... entries) {
      super(entries);
    }

    public Seq0(List<SMIMECapability> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected SMIMECapability newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return SMIMECapability.fromAsn1(coll.getSequenceAt(index));
    }
  }

  /**
   * general preferences
   */
  public static final Asn1Oid preferSignedData = PkcsOIDs.preferSignedData;
  public static final Asn1Oid canNotDecryptAny = PkcsOIDs.canNotDecryptAny;
  public static final Asn1Oid sMIMECapabilitiesVersions = PkcsOIDs.sMIMECapabilitiesVersions;

  /**
   * encryption algorithms preferences
   */
  public static final Asn1Oid dES_CBC = new Asn1Oid("1.3.14.3.2.7");
  public static final Asn1Oid dES_EDE3_CBC = PkcsOIDs.des_EDE3_CBC;
  public static final Asn1Oid aES128_CBC = NistOIDs.id_aes128_CBC;
  public static final Asn1Oid aES192_CBC = NistOIDs.id_aes192_CBC;
  public static final Asn1Oid aES256_CBC = NistOIDs.id_aes256_CBC;

  private final Asn1Oid capabilityID;
  private final Asn1Primitive parameters;

  public static SMIMECapability fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid capabilityID = seq.getOidAt(0);
    Asn1Primitive parameters = size == 1 ? null : seq.getObjectAt(1);
    return new SMIMECapability(capabilityID, parameters);
  }

  public SMIMECapability(Asn1Oid capabilityID, Asn1Primitive parameters) {
    this.capabilityID = Args.notNull(capabilityID, "capabilityID");
    this.parameters = parameters;
  }

  public Asn1Oid getCapabilityID()
  {
      return capabilityID;
  }

  public Asn1Primitive getParameters()
  {
      return parameters;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return parameters == null ? new Asn1Sequence(capabilityID)
        : new Asn1Sequence(capabilityID, parameters);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    capabilityID.toStringNoLineSep(buf, indentLevel, "capabilityID", true);
    if (parameters != null) {
      parameters.toStringNoLineSep(buf, indentLevel + 1, "parameters", true);
    }
    return deleteLastNewLine(buf);
  }
}
