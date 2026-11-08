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
 * The PlatformFirmwareUpdateCompliance object.
 * <pre>
 * PlatformFirmwareUpdateCompliance ::= BIT STRING {
 *     sp800-147  (0),
 *     sp800-147B (1),
 *     sp800-193  (2),
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareUpdateCompliance extends FlagsBitString {

  private static final Set<PlatformFirmwareUpdateCompliance> knownFlags = new HashSet<>(3);
  private static final List<String> names;

  public static final PlatformFirmwareUpdateCompliance sp800_147;

  public static final PlatformFirmwareUpdateCompliance sp800_147B;

  public static final PlatformFirmwareUpdateCompliance sp800_193;

  static {
    List<String> names0 = new ArrayList<>(3);
    sp800_147  = initKnownFlag(names0, 0, "sp800-147");
    sp800_147B = initKnownFlag(names0, 1, "sp800-147B");
    sp800_193  = initKnownFlag(names0, 2, "sp800-193");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<PlatformFirmwareUpdateCompliance> knownAtomicFlags() {
    return knownFlags;
  }

  private static PlatformFirmwareUpdateCompliance initKnownFlag(
      List<String> names, int index, String name) {
    PlatformFirmwareUpdateCompliance flag = new PlatformFirmwareUpdateCompliance(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private PlatformFirmwareUpdateCompliance(int index) {
    super(index);
  }

  public PlatformFirmwareUpdateCompliance(PlatformFirmwareUpdateCompliance... flags) {
    super(flags);
  }

  public static PlatformFirmwareUpdateCompliance fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static PlatformFirmwareUpdateCompliance fromAsn1(Asn1BitString flags) {
    return new PlatformFirmwareUpdateCompliance(Args.notNull(flags, "flags"));
  }

  private PlatformFirmwareUpdateCompliance(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "PlatformFirmwareUpdateCompliance";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
