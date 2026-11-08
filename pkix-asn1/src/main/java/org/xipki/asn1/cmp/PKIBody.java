// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.asn1.crmf.CertReqMessages;
import org.xipki.asn1.pkcs10.CertificationRequest;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * PKIBody ::= CHOICE {       -- message-specific body elements
 *     ir       [0]  CertReqMessages,        --Initialization Request
 *     ip       [1]  CertRepMessage,         --Initialization Response
 *     cr       [2]  CertReqMessages,        --Certification Request
 *     cp       [3]  CertRepMessage,         --Certification Response
 *     p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
 *     popdecc  [5]  POPODecKeyChallContent, --pop Challenge
 *     popdecr  [6]  POPODecKeyRespContent,  --pop Response
 *     kur      [7]  CertReqMessages,        --Key Update Request
 *     kup      [8]  CertRepMessage,         --Key Update Response
 *     krr      [9]  CertReqMessages,        --Key Recovery Request
 *     krp      [10] KeyRecRepContent,       --Key Recovery Response
 *     rr       [11] RevReqContent,          --Revocation Request
 *     rp       [12] RevRepContent,          --Revocation Response
 *     ccr      [13] CertReqMessages,        --Cross-Cert. Request
 *     ccp      [14] CertRepMessage,         --Cross-Cert. Response
 *     ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
 *     cann     [16] CertAnnContent,         --Certificate Ann.
 *     rann     [17] RevAnnContent,          --Revocation Ann.
 *     crlann   [18] CRLAnnContent,          --CRL Announcement
 *     pkiconf  [19] PKIConfirmContent,      --Confirmation
 *     nested   [20] NestedMessageContent,   --Nested Message
 *     genm     [21] GenMsgContent,          --General Message
 *     genp     [22] GenRepContent,          --General Response
 *     error    [23] ErrorMsgContent,        --Error Message
 *     certConf [24] CertConfirmContent,     --Certificate confirm
 *     pollReq  [25] PollReqContent,         --Polling request
 *     pollRep  [26] PollRepContent          --Polling response
 *      }
 *
 * @author Lijun Liao (xipki)
 */
public class PKIBody extends Asn1Encodable {
  //  *     ir       [0]  CertReqMessages,        --Initialization Request
  public static final int tag_ir       = 0;
  // *     ip       [1]  CertRepMessage,         --Initialization Response
  public static final int tag_ip       = 1;
  public static final int tag_cr       = 2;
  public static final int tag_cp       = 3;
  public static final int tag_p10cr    = 4;
  public static final int tag_popdecc  = 5;
  public static final int tag_popdecr  = 6;
  public static final int tag_kur      = 7;
  public static final int tag_kup      = 8;
  public static final int tag_krr      = 9;
  public static final int tag_krp      = 10;
  public static final int tag_rr       = 11;
  public static final int tag_rp       = 12;
  public static final int tag_ccr      = 13;
  public static final int tag_ccp      = 14;
  public static final int tag_ckuann   = 15;
  public static final int tag_cann     = 16;
  public static final int tag_rann     = 17;
  public static final int tag_crlann   = 18;
  public static final int tag_pkiconf  = 19;
  public static final int tag_nested   = 20;
  public static final int tag_genm     = 21;
  public static final int tag_genp     = 22;
  public static final int tag_error    = 23;
  public static final int tag_certConf = 24;
  public static final int tag_pollReq  = 25;
  public static final int tag_pollRep  = 26;

  private static final String[] TAG_NAMES = {"ir", "ip", "cr", "cp", "p10cr", "popdecc",
      "popdecr", "kur", "kup", "krr", "krp", "rr", "rp", "ccr", "ccp", "ckuann", "cann", "rann",
      "crlann", "pkiconf", "nested", "genm", "genp", "error", "certConf", "pollReq", "pollRep"};

  private final int tagNo;

  // *     ir       [0]  CertReqMessages,        --Initialization Request
  private CertReqMessages ir;

  // *     ip       [1]  CertRepMessage,         --Initialization Response
  private CertRepMessage ip;

  // *     cr       [2]  CertReqMessages,        --Certification Request
  private CertReqMessages cr;

  // *     cp       [3]  CertRepMessage,         --Certification Response
  private CertRepMessage cp;

  // *     p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
  private CertificationRequest p10cr;

  // *     popdecc  [5]  POPODecKeyChallContent, --pop Challenge
  private POPODecKeyChallContent popdecc;

  // *     popdecr  [6]  POPODecKeyRespContent,  --pop Response
  private POPODecKeyRespContent popdecr;

  // *     kur      [7]  CertReqMessages,        --Key Update Request
  private CertReqMessages kur;

  // *     kup      [8]  CertRepMessage,         --Key Update Response
  private CertRepMessage kup;

  // *     krr      [9]  CertReqMessages,        --Key Recovery Request
  private CertReqMessages krr;

  // *     krp      [10] KeyRecRepContent,       --Key Recovery Response
  private KeyRecRepContent krp;

  // *     rr       [11] RevReqContent,          --Revocation Request
  private RevReqContent rr;

  // *     rp       [12] RevRepContent,          --Revocation Response
  private RevRepContent rp;

  // *     ccr      [13] CertReqMessages,        --Cross-Cert. Request
  private CertReqMessages ccr;

  // *     ccp      [14] CertRepMessage,         --Cross-Cert. Response
  private CertRepMessage ccp;

  // *     ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
  private CAKeyUpdAnnContent ckuann;

  // *     cann     [16] CertAnnContent,         --Certificate Ann.
  // CertAnnContent ::= CMPCertificate
  private CMPCertificate cann;

  // *     rann     [17] RevAnnContent,          --Revocation Ann.
  private RevAnnContent rann;

  // *     crlann   [18] CRLAnnContent,          --CRL Announcement
  private CRLAnnContent crlann;

  // *     pkiconf  [19] PKIConfirmContent,      --Confirmation
  // PKIConfirmContent ::= NULL
  private Asn1Null pkiconf;

  // *     nested   [20] NestedMessageContent,   --Nested Message
  private PKIMessages nested;

  // *     genm     [21] GenMsgContent,          --General Message
  // NestedMessageContent ::= PKIMessages
  private GenMsgContent genm;

  // *     genp     [22] GenRepContent,          --General Response
  private GenRepContent genp;

  // *     error    [23] ErrorMsgContent,        --Error Message
  private ErrorMsgContent error;

  // *     certConf [24] CertConfirmContent,     --Certificate confirm
  private CertConfirmContent certConf;

  // *     pollReq  [25] PollReqContent,         --Polling request
  private PollReqContent pollReq;

  // *     pollRep  [26] PollRepContent          --Polling response
  private PollRepContent pollRep;

  private PKIBody(int tagNo) {
    this.tagNo = tagNo;
  }

  public static PKIBody fromAsn1(Asn1TaggedObject asn1) throws CodecException {
    int tagNo = asn1.getTagNo();
    switch (tagNo) {
      case tag_ir:
        return ofIr(CertReqMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_ip:
        return ofIp(CertRepMessage.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_cr:
        return ofCr(CertReqMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_cp:
        return ofCp(CertRepMessage.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_p10cr:
        return ofP10cr(CertificationRequest.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_popdecc:
        return ofPopdecc(POPODecKeyChallContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_popdecr:
        return ofPopdecr(POPODecKeyRespContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_kur:
        return ofKur(CertReqMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_kup:
        return ofKup(CertRepMessage.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_krr:
        return ofKrr(CertReqMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_krp:
        return ofKrp(KeyRecRepContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_rr:
        return ofRr(RevReqContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_rp:
        return ofRp(RevRepContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_ccr:
        return ofCcr(CertReqMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_ccp:
        return ofCcp(CertRepMessage.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_ckuann:
        return ofCkuann(CAKeyUpdAnnContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_cann:
        return ofCann(CMPCertificate.fromAsn1(asn1.getExplicitBase()));
      case tag_rann:
        return ofRann(RevAnnContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_crlann:
        return ofCrlann(CRLAnnContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_pkiconf:
        return ofPkiconf();
      case tag_nested:
        return ofNested(PKIMessages.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_genm:
        return ofGenm(GenMsgContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_genp:
        return ofGenp(GenRepContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_error:
        return ofError(ErrorMsgContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_certConf:
        return ofCertConf(CertConfirmContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_pollReq:
        return ofPollReq(PollReqContent.fromAsn1(asn1.getExplicitSequenceBase()));
      case tag_pollRep:
        return ofPollRep(PollRepContent.fromAsn1(asn1.getExplicitSequenceBase()));
      default:
          throw new IllegalArgumentException("unknown tag number: " + tagNo);
    }
  }

  public static PKIBody ofIr(CertReqMessages ir) {
    PKIBody r = new PKIBody(tag_ir);
    r.ir = Args.notNull(ir, "ir");
    return r;
  }

  public static PKIBody ofIp(CertRepMessage ip) {
    PKIBody r = new PKIBody(tag_ip);
    r.ip = Args.notNull(ip, "ip");
    return r;
  }

  public static PKIBody ofCr(CertReqMessages cr) {
    PKIBody r = new PKIBody(tag_cr);
    r.cr = Args.notNull(cr, "cr");
    return r;
  }

  public static PKIBody ofCp(CertRepMessage cp) {
    PKIBody r = new PKIBody(tag_cp);
    r.cp = Args.notNull(cp, "cp");
    return r;
  }

  public static PKIBody ofP10cr(CertificationRequest p10cr) {
    PKIBody r = new PKIBody(tag_p10cr);
    r.p10cr = Args.notNull(p10cr, "p10cr");
    return r;
  }

  public static PKIBody ofPopdecc(POPODecKeyChallContent popdecc) {
    PKIBody r = new PKIBody(tag_popdecc);
    r.popdecc = Args.notNull(popdecc, "popdecc");
    return r;
  }

  public static PKIBody ofPopdecr(POPODecKeyRespContent popdecr) {
    PKIBody r = new PKIBody(tag_popdecr);
    r.popdecr = Args.notNull(popdecr, "popdecr");
    return r;
  }

  public static PKIBody ofKur(CertReqMessages kur) {
    PKIBody r = new PKIBody(tag_kur);
    r.kur = Args.notNull(kur, "kur");
    return r;
  }

  public static PKIBody ofKup(CertRepMessage kup) {
    PKIBody r = new PKIBody(tag_kup);
    r.kup = Args.notNull(kup, "kup");
    return r;
  }

  public static PKIBody ofKrr(CertReqMessages krr) {
    PKIBody r = new PKIBody(tag_krr);
    r.krr = Args.notNull(krr, "krr");
    return r;
  }

  public static PKIBody ofKrp(KeyRecRepContent krp) {
    PKIBody r = new PKIBody(tag_krp);
    r.krp = Args.notNull(krp, "krp");
    return r;
  }

  public static PKIBody ofRr(RevReqContent rr) {
    PKIBody r = new PKIBody(tag_rr);
    r.rr = Args.notNull(rr, "rr");
    return r;
  }

  public static PKIBody ofRp(RevRepContent rp) {
    PKIBody r = new PKIBody(tag_rp);
    r.rp = Args.notNull(rp, "rp");
    return r;
  }

  public static PKIBody ofCcr(CertReqMessages ccr) {
    PKIBody r = new PKIBody(tag_ccr);
    r.ccr = Args.notNull(ccr, "ccr");
    return r;
  }

  public static PKIBody ofCcp(CertRepMessage ccp) {
    PKIBody r = new PKIBody(tag_ccp);
    r.ccp = Args.notNull(ccp, "ccp");
    return r;
  }

  public static PKIBody ofCkuann(CAKeyUpdAnnContent ckuann) {
    PKIBody r = new PKIBody(tag_ckuann);
    r.ckuann = Args.notNull(ckuann, "ckuann");
    return r;
  }

  public static PKIBody ofCann(CMPCertificate cann) {
    PKIBody r = new PKIBody(tag_cann);
    r.cann = Args.notNull(cann, "cann");
    return r;
  }

  public static PKIBody ofRann(RevAnnContent rann) {
    PKIBody r = new PKIBody(tag_rann);
    r.rann = Args.notNull(rann, "rann");
    return r;
  }

  public static PKIBody ofCrlann(CRLAnnContent crlann) {
    PKIBody r = new PKIBody(tag_crlann);
    r.crlann = Args.notNull(crlann, "crlann");
    return r;
  }

  public static PKIBody ofPkiconf() {
    PKIBody r = new PKIBody(tag_pkiconf);
    r.pkiconf = Asn1Null.INSTANCE;
    return r;
  }

  public static PKIBody ofNested(PKIMessages nested) {
    PKIBody r = new PKIBody(tag_nested);
    r.nested = Args.notNull(nested, "nested");
    return r;
  }

  public static PKIBody ofGenm(GenMsgContent genm) {
    PKIBody r = new PKIBody(tag_genm);
    r.genm = Args.notNull(genm, "genm");
    return r;
  }

  public static PKIBody ofGenp(GenRepContent genp) {
    PKIBody r = new PKIBody(tag_genp);
    r.genp = Args.notNull(genp, "genp");
    return r;
  }

  public static PKIBody ofError(ErrorMsgContent error) {
    PKIBody r = new PKIBody(tag_error);
    r.error = Args.notNull(error, "error");
    return r;
  }

  public static PKIBody ofCertConf(CertConfirmContent certConf) {
    PKIBody r = new PKIBody(tag_certConf);
    r.certConf = Args.notNull(certConf, "certConf");
    return r;
  }

  public static PKIBody ofPollReq(PollReqContent pollReq) {
    PKIBody r = new PKIBody(tag_pollReq);
    r.pollReq = Args.notNull(pollReq, "pollReq");
    return r;
  }

  public static PKIBody ofPollRep(PollRepContent pollRep) {
    PKIBody r = new PKIBody(tag_pollRep);
    r.pollRep = Args.notNull(pollRep, "pollRep");
    return r;
  }

  public int getTagNo() {
    return tagNo;
  }

  public Asn1Encodable getChoiceData() {
    switch (tagNo) {
      case tag_ir: return ir;
      case tag_ip: return ip;
      case tag_cr: return cr;
      case tag_cp: return cp;
      case tag_p10cr: return p10cr;
      case tag_popdecc: return popdecc;
      case tag_popdecr: return popdecr;
      case tag_kur: return kur;
      case tag_kup: return kup;
      case tag_krr: return krr;
      case tag_krp: return krp;
      case tag_rr: return rr;
      case tag_rp: return rp;
      case tag_ccr: return ccr;
      case tag_ccp: return ccp;
      case tag_ckuann: return ckuann;
      case tag_cann: return cann;
      case tag_rann: return rann;
      case tag_crlann: return crlann;
      case tag_pkiconf: return pkiconf;
      case tag_nested: return nested;
      case tag_genm: return genm;
      case tag_genp: return genp;
      case tag_error: return error;
      case tag_certConf: return certConf;
      case tag_pollReq: return pollReq;
      case tag_pollRep: return pollRep;
      default:
        throw new IllegalStateException("unkown tag " + tagNo);
    }
  }

  public CertReqMessages getIr() {
    return ir;
  }

  public CertRepMessage getIp() {
    return ip;
  }

  public CertReqMessages getCr() {
    return cr;
  }

  public CertRepMessage getCp() {
    return cp;
  }

  public CertificationRequest getP10cr() {
    return p10cr;
  }

  public POPODecKeyChallContent getPopdecc() {
    return popdecc;
  }

  public POPODecKeyRespContent getPopdecr() {
    return popdecr;
  }

  public CertReqMessages getKur() {
    return kur;
  }

  public CertRepMessage getKup() {
    return kup;
  }

  public CertReqMessages getKrr() {
    return krr;
  }

  public KeyRecRepContent getKrp() {
    return krp;
  }

  public RevReqContent getRr() {
    return rr;
  }

  public RevRepContent getRp() {
    return rp;
  }

  public CertReqMessages getCcr() {
    return ccr;
  }

  public CertRepMessage getCcp() {
    return ccp;
  }

  public CAKeyUpdAnnContent getCkuann() {
    return ckuann;
  }

  public CMPCertificate getCann() {
    return cann;
  }

  public RevAnnContent getRann() {
    return rann;
  }

  public CRLAnnContent getCrlann() {
    return crlann;
  }

  public Asn1Null getPkiconf() {
    return pkiconf;
  }

  public PKIMessages getNested() {
    return nested;
  }

  public GenMsgContent getGenm() {
    return genm;
  }

  public GenRepContent getGenp() {
    return genp;
  }

  public ErrorMsgContent getError() {
    return error;
  }

  public CertConfirmContent getCertConf() {
    return certConf;
  }

  public PollReqContent getPollReq() {
    return pollReq;
  }

  public PollRepContent getPollRep() {
    return pollRep;
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1TaggedObject.newExplicit(tagNo, value());
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    String name = (tagNo >= 0 && tagNo < TAG_NAMES.length) ? TAG_NAMES[tagNo]
        : "[" + tagNo + "]";
    Asn1Encodable value = value();
    return (value instanceof Asn1Null) ? value.toStringNoLineSep(buf, indentLevel, name)
        : value.toStringWithLineSep(buf, indentLevel, name);
  }

  private Asn1Encodable value() {
    switch (tagNo) {
      case tag_ir:
        return ir;
      case tag_ip:
        return ip;
      case tag_cr:
        return cr;
      case tag_cp:
        return cp;
      case tag_p10cr:
        return p10cr;
      case tag_popdecc:
        return popdecc;
      case tag_popdecr:
        return popdecr;
      case tag_kur:
        return kur;
      case tag_kup:
        return kup;
      case tag_krr:
        return krr;
      case tag_krp:
        return krp;
      case tag_rr:
        return rr;
      case tag_rp:
        return rp;
      case tag_ccr:
        return ccr;
      case tag_ccp:
        return ccp;
      case tag_ckuann:
        return ckuann;
      case tag_cann:
        return cann;
      case tag_rann:
        return rann;
      case tag_crlann:
        return crlann;
      case tag_pkiconf:
        return pkiconf;
      case tag_nested:
        return nested;
      case tag_genm:
        return genm;
      case tag_genp:
        return genp;
      case tag_error:
        return error;
      case tag_certConf:
        return certConf;
      case tag_pollReq:
        return pollReq;
      case tag_pollRep:
        return pollRep;
      default:
        throw new IllegalStateException("unknown tag number: " + tagNo);
    }
  }

}
