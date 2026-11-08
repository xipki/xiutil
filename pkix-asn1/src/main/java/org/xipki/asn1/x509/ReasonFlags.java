// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.FlagsBitString;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The ReasonFlags object.
 * <pre>
 * ReasonFlags ::= BIT STRING {
 *      unused                  (0),
 *      keyCompromise           (1),
 *      cACompromise            (2),
 *      affiliationChanged      (3),
 *      superseded              (4),
 *      cessationOfOperation    (5),
 *      certificateHold         (6),
 *      privilegeWithdrawn      (7),
 *      aACompromise            (8) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ReasonFlags extends FlagsBitString {

  private static final Set<ReasonFlags> knownFlags = new HashSet<>(9);
  private static final List<String> names;

  public static final ReasonFlags unused;
  public static final ReasonFlags keyCompromise;
  public static final ReasonFlags cACompromise;
  public static final ReasonFlags affiliationChanged;
  public static final ReasonFlags superseded;
  public static final ReasonFlags cessationOfOperation;
  public static final ReasonFlags certificateHold;
  public static final ReasonFlags privilegeWithdrawn;
  public static final ReasonFlags aACompromise;

  static {
    List<String> names0 = new ArrayList<>(9);
    unused               = initKnownFlag(names0, 0, "unused");
    keyCompromise        = initKnownFlag(names0, 1, "keyCompromise");
    cACompromise         = initKnownFlag(names0, 2, "cACompromise");
    affiliationChanged   = initKnownFlag(names0, 3, "affiliationChanged");
    superseded           = initKnownFlag(names0, 4, "superseded");
    cessationOfOperation = initKnownFlag(names0, 5, "cessationOfOperation");
    certificateHold      = initKnownFlag(names0, 6, "certificateHold");
    privilegeWithdrawn   = initKnownFlag(names0, 7, "privilegeWithdrawn");
    aACompromise         = initKnownFlag(names0, 8, "aACompromise");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<ReasonFlags> knownAtomicFlags() {
    return knownFlags;
  }

  private static ReasonFlags initKnownFlag(List<String> names, int index, String name) {
    ReasonFlags flag = new ReasonFlags(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private ReasonFlags(int index) {
    super(index);
  }

  public ReasonFlags(ReasonFlags... flags) {
    super(flags);
  }

  public static ReasonFlags fromAsn1(Asn1BitString flags) {
    return new ReasonFlags(Args.notNull(flags, "flags"));
  }

  private ReasonFlags(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "ReasonFlags";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
