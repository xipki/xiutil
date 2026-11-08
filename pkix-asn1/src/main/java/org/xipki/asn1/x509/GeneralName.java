// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.asn1.x500.X500Name;
import org.xipki.codec.asn1.*;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.ipadress.IPAddressUtil;

import java.util.List;

/**
 * The GeneralName object.
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER}
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner [0] DirectoryString OPTIONAL,
 *      partyName    [1] DirectoryString }
 *
 * Name ::= CHOICE { RDNSequence }
 *
 * ORAddress ::= SEQUENCE {
 *     built-in-standard-attributes BuiltInStandardAttributes,
 *     built-in-domain-defined-attributes
 *         BuiltInDomainDefinedAttributes OPTIONAL,
 *     extension-attributes ExtensionAttributes OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralName extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<GeneralName> {

    public Seq1(GeneralName... entries) {
      super(entries);
    }

    public Seq1(List<GeneralName> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected GeneralName newType(AbstractAsn1Collection coll, int index) throws CodecException {
      return GeneralName.fromAsn1(coll.getTaggedAt(index));
    }
  }

  public static final int tag_otherName     = 0;
  public static final int tag_rfc822Name    = 1;
  public static final int tag_dNSName       = 2;
  public static final int tag_x400Address   = 3;
  public static final int tag_directoryName = 4;
  public static final int tag_ediPartyName  = 5;
  public static final int tag_uri           = 6;
  public static final int tag_iPAddress     = 7;
  public static final int tag_registeredID  = 8;

  private final int tagNo;

  private OtherName otherName;

  private Asn1IA5String rfc822Name;

  private Asn1IA5String dNSName;

  private Asn1Sequence x400Address;

  private X500Name directoryName;

  private EDIPartyName ediPartyName;

  private Asn1IA5String uri;

  private Asn1OctetString iPAddress;

  private Asn1Oid registeredID;

  private GeneralName(int tagNo) {
    this.tagNo = tagNo;
  }

  //   private OtherName otherName;
  public static GeneralName ofOtherName(OtherName otherName) {
    GeneralName r = new GeneralName(tag_otherName);
    r.otherName = Args.notNull(otherName, "otherName");
    return r;
  }

  public static GeneralName ofRfc822Name(Asn1IA5String rfc822Name) {
    GeneralName r = new GeneralName(tag_rfc822Name);
    r.rfc822Name = Args.notNull(rfc822Name, "rfc822Name");
    return r;
  }

  public static GeneralName ofRfc822Name(String rfc822Name) {
    return ofRfc822Name(Asn1Util.toIA5String(rfc822Name));
  }

  public static GeneralName ofDnsName(Asn1IA5String dNSName) {
    GeneralName r = new GeneralName(tag_dNSName);
    r.dNSName = Args.notNull(dNSName, "dNSName");
    return r;
  }

  public static GeneralName ofDnsName(String dNSName) {
    return ofDnsName(Asn1Util.toIA5String(dNSName));
  }

  public static GeneralName ofX400Address(Asn1Sequence x400Address) {
    GeneralName r = new GeneralName(tag_x400Address);
    r.x400Address = Args.notNull(x400Address, "x400Address");
    return r;
  }

  public static GeneralName ofDirectoryName(X500Name directoryName) {
    GeneralName r = new GeneralName(tag_directoryName);
    r.directoryName = Args.notNull(directoryName, "directoryName");
    return r;
  }

  public static GeneralName ofEdiPartyName(EDIPartyName ediPartyName) {
    GeneralName r = new GeneralName(tag_ediPartyName);
    r.ediPartyName = Args.notNull(ediPartyName, "ediPartyName");
    return r;
  }

  public static GeneralName ofUri(Asn1IA5String uri) {
    GeneralName r = new GeneralName(tag_uri);
    r.uri = Args.notNull(uri, "uri");
    return r;
  }

  public static GeneralName ofUri(String uri) {
    return ofUri(Asn1Util.toIA5String(uri));
  }

  public static GeneralName ofIPAddress(String iPAddress) {
    byte[] enc = IPAddressUtil.ipAddrToGeneralNameEncoding(iPAddress);
    if (enc == null) {
      throw new IllegalArgumentException("IP Address is invalid");
    }
    return ofIPAddress(new Asn1OctetString(enc));
  }

  public static GeneralName ofIPAddress(Asn1OctetString iPAddress) {
    GeneralName r = new GeneralName(tag_iPAddress);
    r.iPAddress = Args.notNull(iPAddress, "iPAddress");
    return r;
  }

  public static GeneralName ofRegisteredID(Asn1Oid registeredID) {
    GeneralName r = new GeneralName(tag_registeredID);
    r.registeredID = Args.notNull(registeredID, "registeredID");
    return r;
  }

  public static GeneralName ofTagName(int tag, String name) {
    Args.notNull(name, "name");
    if (tag == tag_rfc822Name) {
      return ofRfc822Name(new Asn1IA5String(name));
    } else if (tag == tag_dNSName) {
      return ofDnsName(new Asn1IA5String(name));
    } else if (tag == tag_uri) {
      return ofUri(new Asn1IA5String(name));
    } else if (tag == tag_registeredID) {
      return ofRegisteredID(new Asn1Oid(name));
    } else if (tag == tag_directoryName) {
      return ofDirectoryName(new X500Name(name));
    } else if (tag == tag_iPAddress) {
      byte[] enc = IPAddressUtil.ipAddrToGeneralNameEncoding(name);
      if (enc == null) {
        throw new IllegalArgumentException("IP Address is invalid");
      }
      return ofIPAddress(new Asn1OctetString(enc));
    } else {
      throw new IllegalArgumentException("can't process String for tag: " + tag);
    }
  }

  public static GeneralName fromAsn1(Asn1TaggedObject tagObj) throws CodecException {
    int tag = tagObj.getTagNo();
    if (tag == tag_otherName) {
      return ofOtherName(OtherName.fromAsn1(tagObj.getImplicitSequenceBase()));
    } else if (tag == tag_dNSName) {
      return ofDnsName(tagObj.getImplicitIA5StringBase());
    } else if (tag == tag_rfc822Name) {
      return ofRfc822Name(tagObj.getImplicitIA5StringBase());
    } else if (tag == tag_uri) {
      return ofUri(tagObj.getImplicitIA5StringBase());
    } else if (tag == tag_directoryName) {
      // CHOICE -> EXPLICIT
      return ofDirectoryName(X500Name.fromAsn1(tagObj.getExplicitSequenceBase()));
    } else if (tag == tag_iPAddress) {
      return ofIPAddress(tagObj.getImplicitOctetStringBase());
    } else if (tag == tag_registeredID) {
      return ofRegisteredID(tagObj.getImplicitOidBase());
    } else if (tag == tag_ediPartyName) {
      return ofEdiPartyName(EDIPartyName.fromAsn1(tagObj.getImplicitSequenceBase()));
    } else if (tag == tag_x400Address) {
      return ofX400Address(tagObj.getImplicitSequenceBase());
    } else {
      throw new CodecException("unknown tag: " + tag);
    }
  }

  public int getTagNo() {
    return tagNo;
  }

  public Asn1Encodable getChoiceData() {
    return directoryName != null ? directoryName
        : otherName      != null ? otherName
        : rfc822Name     != null ? rfc822Name
        : dNSName        != null ? dNSName
        : x400Address    != null ? x400Address
        : ediPartyName   != null ? ediPartyName
        : uri            != null ? uri
        : iPAddress      != null ? iPAddress
        : registeredID;
  }

  public OtherName getOtherName() {
    return otherName;
  }

  public Asn1IA5String getRfc822Name() {
    return rfc822Name;
  }

  public Asn1IA5String getDNSName() {
    return dNSName;
  }

  public Asn1Primitive getX400Address() {
    return x400Address;
  }

  public X500Name getDirectoryName() {
    return directoryName;
  }

  public EDIPartyName getEdiPartyName() {
    return ediPartyName;
  }

  public Asn1IA5String getUri() {
    return uri;
  }

  public Asn1OctetString getIPAddress() {
    return iPAddress;
  }

  public Asn1Oid getRegisteredID() {
    return registeredID;
  }

  public String rfc822Name() {
    return Asn1Util.fromAsn1(rfc822Name);
  }

  public String dNSName() {
    return Asn1Util.fromAsn1(dNSName);
  }

  public String uri() {
    return Asn1Util.fromAsn1(uri);
  }

  public byte[] IPAddress() {
    return Asn1Util.fromAsn1(iPAddress);
  }

  public Asn1Encodable getValue() {
    if (tagNo == tag_otherName) {
      return otherName;
    } else if (tagNo == tag_dNSName) {
      return dNSName;
    } else if (tagNo == tag_rfc822Name) {
      return rfc822Name;
    } else if (tagNo == tag_uri) {
      return uri;
    } else if (tagNo == tag_directoryName) {
      return directoryName;
    } else if (tagNo == tag_iPAddress) {
      return iPAddress;
    } else if (tagNo == tag_registeredID) {
      return registeredID;
    } else if (tagNo == tag_ediPartyName) {
      return ediPartyName;
    } else if (tagNo == tag_x400Address) {
      return x400Address;
    } else {
      throw new IllegalStateException("unknown tagNo: " + tagNo);
    }
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    // directoryName is explicitly tagged as it is a CHOICE
    boolean explicit = (tagNo == tag_directoryName);
    return new Asn1TaggedObject(explicit, tagNo, getValue());
  }

  private Asn1Encodable parsedValue() {
    if (otherName != null) {
      return otherName;
    } else if (rfc822Name != null) {
      return rfc822Name;
    } else if (dNSName != null) {
      return dNSName;
    } else if (x400Address != null) {
      return x400Address;
    } else if (directoryName != null) {
      return directoryName;
    } else if (ediPartyName != null) {
      return ediPartyName;
    } else if (uri != null) {
      return uri;
    } else if (iPAddress != null) {
      return iPAddress;
    } else { // if (registeredID != null) {
      return registeredID;
    }
  }

  @Override
  public int hashCode() {
    return tagNo * 31 + parsedValue().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof GeneralName)) {
      return false;
    }

    GeneralName b = (GeneralName) obj;
    return tagNo == b.tagNo && parsedValue().equals(b.parsedValue());
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    switch (tagNo) {
      case tag_otherName:
      case tag_x400Address:
      case tag_ediPartyName:
        return parsedValue().toStringWithLineSep(buf, indentLevel, getTagName());
      default:
        return parsedValue().toStringNoLineSep(buf, indentLevel, getTagName());
    }
  }

  private String getTagName() {
    switch (tagNo) {
      case tag_otherName: return "otherName";
      case tag_rfc822Name: return "rfc822Name";
      case tag_dNSName: return "dNSName";
      case tag_x400Address: return "x400Name";
      case tag_directoryName: return "directoryName";
      case tag_ediPartyName: return "tag_ediPartyName";
      case tag_uri: return "uri";
      case tag_iPAddress: return "iPAddress";
      case tag_registeredID: return "registeredID";
      default:
        throw new IllegalStateException("unknown tagNo " + tagNo);
    }
  }

}
