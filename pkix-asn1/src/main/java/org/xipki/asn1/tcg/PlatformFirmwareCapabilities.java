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
 * The PlatformFirmwareCapabilities object.
 * <pre>
 * PlatformFirmwareCapabilities ::= BIT STRING {
 *     fwSetupAuthLocal (0),
 *     fwSetupAuthRemote (1),
 *     sMMProtection (2),
 *     fwKernelDMAProtection (3)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareCapabilities extends FlagsBitString {

  private static final Set<PlatformFirmwareCapabilities> knownFlags = new HashSet<>(4);
  private static final List<String> names;

  public static final PlatformFirmwareCapabilities fwSetupAuthLocal;

  public static final PlatformFirmwareCapabilities fwSetupAuthRemote;

  public static final PlatformFirmwareCapabilities sMMProtection;

  public static final PlatformFirmwareCapabilities fwKernelDMAProtection;

  static {
    List<String> names0 = new ArrayList<>(4);
    fwSetupAuthLocal      = initKnownFlag(names0, 0, "fwSetupAuthLocal");
    fwSetupAuthRemote     = initKnownFlag(names0, 1, "fwSetupAuthRemote");
    sMMProtection         = initKnownFlag(names0, 2, "sMMProtection");
    fwKernelDMAProtection = initKnownFlag(names0, 3, "fwKernelDMAProtection");
    names = Collections.unmodifiableList(names0);
  }
  public static Set<PlatformFirmwareCapabilities> knownAtomicFlags() {
    return knownFlags;
  }

  private static PlatformFirmwareCapabilities initKnownFlag(
      List<String> names, int index, String name) {
    PlatformFirmwareCapabilities flag = new PlatformFirmwareCapabilities(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private PlatformFirmwareCapabilities(int index) {
    super(index);
  }

  public PlatformFirmwareCapabilities(PlatformFirmwareCapabilities... flags) {
    super(flags);
  }

  public static PlatformFirmwareCapabilities fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static PlatformFirmwareCapabilities fromAsn1(Asn1BitString flags) {
    return new PlatformFirmwareCapabilities(Args.notNull(flags, "flags"));
  }

  private PlatformFirmwareCapabilities(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "PlatformFirmwareCapabilities";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
