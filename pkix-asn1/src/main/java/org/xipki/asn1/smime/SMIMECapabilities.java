// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.smime;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.List;

/**
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 * SMIMECapabilities ::= SEQUENCE OF SMIMECapability
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SMIMECapabilities extends SMIMECapability.Seq0 {

  public SMIMECapabilities(SMIMECapability... entries) {
    super(entries);
  }

  public SMIMECapabilities(List<SMIMECapability> entries) {
    super(entries);
  }

  private SMIMECapabilities(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static SMIMECapabilities fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SMIMECapabilities fromAsn1(Asn1Sequence seq) throws CodecException {
    return new SMIMECapabilities(seq);
  }

  /**
   * returns a vector with 0 or more objects of all the capabilities
   * matching the passed in capability OID. If the OID passed is null the
   * entire set is returned.
   */
  public List<SMIMECapability> getCapabilities(Asn1Oid capability) {
    if (capability == null) {
      return entries;
    }

    List<SMIMECapability> r = new ArrayList<>(1);
    for (SMIMECapability m : entries) {
      if (m.getCapabilityID().equals(capability)) {
        r.add(m);
      }
    }

    return r;
  }

}
