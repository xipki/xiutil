// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.PrimitiveType;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * PKIX RFC-2459 - TBSCertList object.
 * <pre>
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, shall be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *      }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                         -- if present, shall be v2
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TBSCertList extends Asn1Encodable {

  public static class V2Generator {

    private final Asn1Integer version = Asn1Integer.ONE;
    private AlgorithmIdentifier signature;
    private X500Name issuer;
    private Time thisUpdate, nextUpdate=null;
    private Extensions extensions = null;
    private final List<CRLEntry> crlEntries = new LinkedList<>();

    private final static Extension[] reasonExtensions;

    static {
      reasonExtensions = new Extension[11];

      CRLReason[] reasons = {
          CRLReason.unspecified,  CRLReason.keyCompromise,
          CRLReason.cACompromise, CRLReason.affiliationChanged,
          CRLReason.superseded,   CRLReason.cessationOfOperation,
          CRLReason.certificateHold,    CRLReason.removeFromCRL,
          CRLReason.privilegeWithdrawn, CRLReason.aACompromise};

      for (CRLReason reason : reasons) {
        reasonExtensions[reason.getValue()] = createReasonExtension(reason);
      }
    }

    public V2Generator() {
    }

    public void setSignature(AlgorithmIdentifier signature) {
      this.signature = signature;
    }

    public void setIssuer(X500Name issuer) {
      this.issuer = issuer;
    }

    public void setThisUpdate(Instant thisUpdate) {
      this.thisUpdate = new Time(thisUpdate);
    }

    public void setNextUpdate(Instant nextUpdate) {
      this.nextUpdate = new Time(nextUpdate);
    }

    public void addCRLEntry(BigInteger userCertificate, Instant revocationDate, CRLReason reason) {
      addCRLEntry(userCertificate, revocationDate, reason, null);
    }

    public void addCRLEntry(BigInteger userCertificate, Instant revocationDate,
                            CRLReason reason, Instant invalidityDate) {
      int reasonCode = reason.getValue();
      Extensions extensions;
      if (reasonCode == 0 && invalidityDate == null) {
        extensions = null;
      } else {
        List<Extension> v = new ArrayList<>(2);
        if (reasonCode != 0) {
          v.add(reasonExtensions[reasonCode]);
        }

        if (invalidityDate != null) {
          v.add(Extension.ofInvalidityDate(false, invalidityDate));
        }

        extensions = new Extensions(v);
      }

      crlEntries.add(new CRLEntry(userCertificate, revocationDate, extensions));
    }

    public void addCRLEntry(BigInteger userCertificate, Instant revocationDate,
                            Extensions extensions) {
      crlEntries.add(new CRLEntry(new Asn1Integer(userCertificate),
          new Time(revocationDate), extensions));
    }

    public void addCRLEntry(Asn1Integer userCertificate, Time revocationDate,
                            Extensions extensions) {
      crlEntries.add(new CRLEntry(userCertificate, revocationDate, extensions));
    }

    public void addCRLEntry(CRLEntry entry) {
      crlEntries.add(Args.notNull(entry, "entry"));
    }

    public void setExtensions(Extensions extensions) {
      this.extensions = extensions;
    }

    public TBSCertList generateTBSCertList() throws CodecException {
      return new TBSCertList(signature, issuer, thisUpdate, nextUpdate, crlEntries, extensions);
    }

    private static Extension createReasonExtension(CRLReason reason) {
      return Extension.ofReasonCode(false, reason);
    }

  }

  private final Asn1Integer version;
  private final AlgorithmIdentifier signature;
  private final X500Name issuer;
  private final Time thisUpdate;
  private final Time nextUpdate;
  private final Asn1Sequence revokedCertificates;
  private final Extensions crlExtensions;

  public TBSCertList(
      AlgorithmIdentifier signature, X500Name issuer, Time thisUpdate, Time nextUpdate,
      List<CRLEntry> revokedCertificates, Extensions crlExtensions) {
    this.version = Asn1Integer.ONE;
    this.signature = Args.notNull(signature, "signature");
    this.issuer = Args.notNull(issuer, "issuer");
    if (this.issuer.size() == 0) {
      throw new IllegalStateException("issuer is an empty distinguished name");
    }

    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = nextUpdate;
    this.revokedCertificates = revokedCertificates == null || revokedCertificates.isEmpty()
        ? null : new Asn1Sequence(revokedCertificates);
    this.crlExtensions = crlExtensions;
  }

  public static TBSCertList fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 3, 7);
    int index = 0;

    Asn1Integer version = seq.notHasType(index, PrimitiveType.INTEGER) ? Asn1Integer.ZERO
        : seq.getNonNegativeIntegerAt(index++);

    if (!(version.hasValue(0) || version.hasValue(1))) {
      throw new CodecException("invalid version " + version);
    }

    AlgorithmIdentifier signature = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));
    X500Name issuer = X500Name.fromAsn1(seq.getSequenceAt(index++));
    if (issuer.size() == 0) {
      throw new CodecException("CRL issuer is an empty distinguished name");
    }
    Time thisUpdate = Time.fromAsn1(seq.getTimeAt(index++));

    Time nextUpdate = seq.hasAnyType(index, PrimitiveType.UTC_TIME, PrimitiveType.GENERALIZED_TIME)
        ? Time.fromAsn1(seq.getTimeAt(index++)) : null;

    Asn1Sequence revokedCertificates = seq.notHasType(index, PrimitiveType.SEQUENCE) ? null
        : seq.getSequenceAt(index++);

    Extensions crlExtensions = seq.isNotTaggedAt(index, 0) ? null
        : Extensions.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index, size);

    if (version.hasValue(0) && crlExtensions != null) {
      throw new CodecException("V1 CRL does not allow CRL extensions");
    }

    return new TBSCertList(version, signature, issuer, thisUpdate, nextUpdate,
        revokedCertificates, crlExtensions);
  }

  private TBSCertList(
      Asn1Integer version, AlgorithmIdentifier signature, X500Name issuer, Time thisUpdate,
      Time nextUpdate, Asn1Sequence revokedCertificates, Extensions crlExtensions) {
    this.version = version;
    this.signature = signature;
    this.issuer = issuer;
    this.thisUpdate = thisUpdate;
    this.nextUpdate = nextUpdate;
    this.revokedCertificates = revokedCertificates;
    this.crlExtensions = crlExtensions;
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public AlgorithmIdentifier getSignature() {
    return signature;
  }

  public X500Name getIssuer() {
    return issuer;
  }

  public Time getThisUpdate() {
    return thisUpdate;
  }

  public Time getNextUpdate() {
    return nextUpdate;
  }

  public int version() {
    return version.intValueExact();
  }

  public Instant thisUpdate() {
    return thisUpdate.time();
  }

  public Instant nextUpdate() {
    return Asn1Util.fromAsn1(nextUpdate);
  }

  public Extension getExtension(Asn1Oid extensionId) {
    return crlExtensions == null ? null : crlExtensions.getExtension(extensionId);
  }

  public List<CRLEntry> getRevokedCertificates() throws CodecException {
    if (revokedCertificates == null) {
      return Collections.emptyList();
    }

    int size = revokedCertificates.size();
    List<CRLEntry> entries = new ArrayList<>(size);

    for (int i = 0; i < size; i++) {
      entries.add(CRLEntry.fromAsn1(revokedCertificates.getSequenceAt(i)));
    }

    return entries;
  }

  public Extensions getExtensions() {
    return crlExtensions;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    Asn1Integer asn1Version = version.hasValue(0) ? null : version;
    Asn1TaggedObject asn1Extensions = (crlExtensions == null) ? null
        : new Asn1TaggedObject(true, 0, crlExtensions);

    return Asn1Sequence.buildIgnoreNull(asn1Version, signature, issuer,
        thisUpdate, nextUpdate, revokedCertificates, asn1Extensions);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    signature.toStringWithLineSep(buf, indentLevel, "signature", true);
    issuer.toStringNoLineSep(buf, indentLevel, "issuer", true);
    thisUpdate.toStringNoLineSep(buf, indentLevel, "thisUpdate", true);

    if (nextUpdate != null) {
      nextUpdate.toStringNoLineSep(buf, indentLevel, "nextUpdate", true);
    }

    // a CRL may have very many entries: only the number is printed
    ToStringUtil.appendIndent(buf, indentLevel, "revokedCertificates: "
        + (revokedCertificates == null ? 0 : revokedCertificates.size()) + " entries\n");

    if (crlExtensions != null) {
      crlExtensions.toStringWithLineSep(buf, indentLevel, "crlExtensions", true);
    }

    return deleteLastNewLine(buf);
  }

}
