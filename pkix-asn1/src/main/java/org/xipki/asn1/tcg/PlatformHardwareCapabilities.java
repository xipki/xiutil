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
 * The PlatformHardwareCapabilities object.
 * <pre>
 * PlatformHardwareCapabilities ::= BIT STRING {
 *     iOMMUSupport                (0),
 *     trustedExecutionEnvironment (1),
 *     physicalTamperProtection    (2),
 *     physicalTamperDetection     (3),
 *     firmwareFlashWP             (4),
 *     externalDMASupport          (5)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformHardwareCapabilities extends FlagsBitString {

  private static final Set<PlatformHardwareCapabilities> knownFlags = new HashSet<>(6);
  private static final List<String> names;

  public static final PlatformHardwareCapabilities iOMMUSupport;

  public static final PlatformHardwareCapabilities trustedExecutionEnvironment;

  public static final PlatformHardwareCapabilities physicalTamperProtection;

  public static final PlatformHardwareCapabilities physicalTamperDetection;

  public static final PlatformHardwareCapabilities firmwareFlashWP;

  public static final PlatformHardwareCapabilities externalDMASupport;

  static {
    List<String> names0 = new ArrayList<>(6);
    iOMMUSupport                = initKnownFlag(names0, 0, "iOMMUSupport");
    trustedExecutionEnvironment = initKnownFlag(names0, 1, "trustedExecutionEnvironment");
    physicalTamperProtection    = initKnownFlag(names0, 2, "physicalTamperProtection");
    physicalTamperDetection     = initKnownFlag(names0, 3, "physicalTamperDetection");
    firmwareFlashWP             = initKnownFlag(names0, 4, "firmwareFlashWP");
    externalDMASupport          = initKnownFlag(names0, 5, "externalDMASupport");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<PlatformHardwareCapabilities> knownAtomicFlags() {
    return knownFlags;
  }

  private static PlatformHardwareCapabilities initKnownFlag(
      List<String> names, int index, String name) {
    PlatformHardwareCapabilities flag = new PlatformHardwareCapabilities(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private PlatformHardwareCapabilities(int index) {
    super(index);
  }

  public PlatformHardwareCapabilities(PlatformHardwareCapabilities... flags) {
    super(flags);
  }

  public static PlatformHardwareCapabilities fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static PlatformHardwareCapabilities fromAsn1(Asn1BitString flags) {
    return new PlatformHardwareCapabilities(Args.notNull(flags, "flags"));
  }

  private PlatformHardwareCapabilities(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "PlatformHardwareCapabilities";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
