// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.cmp;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.FlagsBitString;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <pre>
 * PKIFailureInfo ::= BIT STRING {
 *     badAlg               (0),
 *       -- unrecognized or unsupported Algorithm Identifier
 *     badMessageCheck      (1), -- integrity check failed (e.g., signature did not verify)
 *     badRequest           (2),
 *       -- transaction not permitted or supported
 *     badTime              (3), -- messageTime was not sufficiently close to the system time,
 *                               -- as defined by local policy
 *     badCertId            (4), -- no certificate could be found matching the provided criteria
 *     badDataFormat        (5),
 *       -- the data submitted has the wrong format
 *     wrongAuthority       (6), -- the authority indicated in the request is different from the
 *                               -- one creating the response token
 *     incorrectData        (7), -- the requester's data is incorrect (for notary services)
 *     missingTimeStamp     (8), -- when the timestamp is missing but should be there (by policy)
 *     badPOP               (9)  -- the proof-of-possession failed
 *     certRevoked         (10),
 *     certConfirmed       (11),
 *     wrongIntegrity      (12),
 *     badRecipientNonce   (13),
 *     timeNotAvailable    (14),
 *       -- the TSA's time source is not available
 *     unacceptedPolicy    (15),
 *       -- the requested TSA policy is not supported by the TSA
 *     unacceptedExtension (16),
 *       -- the requested extension is not supported by the TSA
 *     addInfoNotAvailable (17)
 *       -- the additional information requested could not be understood
 *       -- or is not available
 *     badSenderNonce      (18),
 *     badCertTemplate     (19),
 *     signerNotTrusted    (20),
 *     transactionIdInUse  (21),
 *     unsupportedVersion  (22),
 *     notAuthorized       (23),
 *     systemUnavail       (24),
 *     systemFailure       (25),
 *       -- the request cannot be handled due to system failure
 *     duplicateCertReq    (26)
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PKIFailureInfo extends FlagsBitString {

  private static final Set<PKIFailureInfo> knownFlags = new HashSet<>(27);
  private static final List<String> names;

  public static final PKIFailureInfo badAlg;
  public static final PKIFailureInfo badMessageCheck;
  public static final PKIFailureInfo badRequest;
  public static final PKIFailureInfo badTime;
  public static final PKIFailureInfo badCertId;
  public static final PKIFailureInfo badDataFormat;
  public static final PKIFailureInfo wrongAuthority;
  public static final PKIFailureInfo incorrectData;
  public static final PKIFailureInfo missingTimeStamp;
  public static final PKIFailureInfo badPOP;
  public static final PKIFailureInfo certRevoked;
  public static final PKIFailureInfo certConfirmed;
  public static final PKIFailureInfo wrongIntegrity;
  public static final PKIFailureInfo badRecipientNonce;
  public static final PKIFailureInfo timeNotAvailable;
  public static final PKIFailureInfo unacceptedPolicy;
  public static final PKIFailureInfo unacceptedExtension;
  public static final PKIFailureInfo addInfoNotAvailable;
  public static final PKIFailureInfo badSenderNonce;
  public static final PKIFailureInfo badCertTemplate;
  public static final PKIFailureInfo signerNotTrusted;
  public static final PKIFailureInfo transactionIdInUse;
  public static final PKIFailureInfo unsupportedVersion;
  public static final PKIFailureInfo notAuthorized;
  public static final PKIFailureInfo systemUnavail;
  public static final PKIFailureInfo systemFailure;
  public static final PKIFailureInfo duplicateCertReq;

  static {
    List<String> names0 = new ArrayList<>(27);
    badAlg              = initKnownFlag(names0, 0, "badAlg");
    badMessageCheck     = initKnownFlag(names0, 1, "badMessageCheck");
    badRequest          = initKnownFlag(names0, 2, "badRequest");
    badTime             = initKnownFlag(names0, 3, "badTime");
    badCertId           = initKnownFlag(names0, 4, "badCertId");
    badDataFormat       = initKnownFlag(names0, 5, "badDataFormat");
    wrongAuthority      = initKnownFlag(names0, 6, "wrongAuthority");
    incorrectData       = initKnownFlag(names0, 7, "incorrectData");
    missingTimeStamp    = initKnownFlag(names0, 8, "missingTimeStamp");
    badPOP              = initKnownFlag(names0, 9, "badPOP");
    certRevoked         = initKnownFlag(names0, 10, "certRevoked");
    certConfirmed       = initKnownFlag(names0, 11, "certConfirmed");
    wrongIntegrity      = initKnownFlag(names0, 12, "wrongIntegrity");
    badRecipientNonce   = initKnownFlag(names0, 13, "badRecipientNonce");
    timeNotAvailable    = initKnownFlag(names0, 14, "timeNotAvailable");
    unacceptedPolicy    = initKnownFlag(names0, 15, "unacceptedPolicy");
    unacceptedExtension = initKnownFlag(names0, 16, "unacceptedExtension");
    addInfoNotAvailable = initKnownFlag(names0, 17, "addInfoNotAvailable");
    badSenderNonce      = initKnownFlag(names0, 18, "badSenderNonce");
    badCertTemplate     = initKnownFlag(names0, 19, "badCertTemplate");
    signerNotTrusted    = initKnownFlag(names0, 20, "signerNotTrusted");
    transactionIdInUse  = initKnownFlag(names0, 21, "transactionIdInUse");
    unsupportedVersion  = initKnownFlag(names0, 22, "unsupportedVersion");
    notAuthorized       = initKnownFlag(names0, 23, "notAuthorized");
    systemUnavail       = initKnownFlag(names0, 24, "systemUnavail");
    systemFailure       = initKnownFlag(names0, 25, "systemFailure");
    duplicateCertReq    = initKnownFlag(names0, 26, "duplicateCertReq");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<PKIFailureInfo> knownAtomicFlags() {
    return knownFlags;
  }

  private static PKIFailureInfo initKnownFlag(List<String> names, int index, String name) {
    PKIFailureInfo flag = new PKIFailureInfo(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private PKIFailureInfo(int index) {
    super(index);
  }

  public PKIFailureInfo(PKIFailureInfo... flags) {
    super(flags);
  }

  public static PKIFailureInfo fromAsn1(Asn1BitString flags) {
    return new PKIFailureInfo(Args.notNull(flags, "flags"));
  }

  private PKIFailureInfo(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "PKIFailureInfo";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
