// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.tcg;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.FlagsBitString;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The RTMTypes object.
 * <pre>
 * RTMTypes ::= BIT STRING {
 *     static         (0),
 *     dynamic        (1),
 *     nonHost        (2),
 *     virtual        (3),
 *     hardwareStatic (4),
 *     bMC            (5)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RTMTypes extends FlagsBitString {

  private static final Set<RTMTypes> knownFlags = new HashSet<>(6);
  private static final List<String> names;

  public static final RTMTypes _static;
  public static final RTMTypes dynamic;
  public static final RTMTypes nonHost;
  public static final RTMTypes virtual;
  public static final RTMTypes hardwareStatic;
  public static final RTMTypes bMC;

  static {
    List<String> names0 = new ArrayList<>(6);
    _static        = initKnownFlag(names0, 0, "static");
    dynamic        = initKnownFlag(names0, 1, "dynamic");
    nonHost        = initKnownFlag(names0, 2, "nonHost");
    virtual        = initKnownFlag(names0, 3, "virtual");
    hardwareStatic = initKnownFlag(names0, 4, "hardwareStatic");
    bMC            = initKnownFlag(names0, 5, "bMC");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<RTMTypes> knownAtomicFlags() {
    return knownFlags;
  }

  private static RTMTypes initKnownFlag(List<String> names, int index, String name) {
    RTMTypes flag = new RTMTypes(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private RTMTypes(int index) {
    super(index);
  }

  public RTMTypes(RTMTypes... flags) {
    super(flags);
  }

  public static RTMTypes fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static RTMTypes fromAsn1(Asn1BitString flags) {
    return new RTMTypes(Args.notNull(flags, "flags"));
  }

  private RTMTypes(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "RTMTypes";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
