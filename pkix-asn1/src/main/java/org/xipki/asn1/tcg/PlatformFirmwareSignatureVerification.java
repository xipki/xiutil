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
 * The PlatformFirmwareSignatureVerification object.
 * <pre>
 * PlatformFirmwareSignatureVerification ::= BIT STRING {
 *     hardwareSRTM (0),
 *     secureBoot   (1)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareSignatureVerification extends FlagsBitString {

  private static final Set<PlatformFirmwareSignatureVerification> knownFlags = new HashSet<>(2);
  private static final List<String> names;

  public static final PlatformFirmwareSignatureVerification hardwareSRTM;

  public static final PlatformFirmwareSignatureVerification secureBoot;

  static {
    List<String> names0 = new ArrayList<>(2);
    hardwareSRTM = initKnownFlag(names0, 0, "hardwareSRTM");
    secureBoot   = initKnownFlag(names0, 1, "secureBoot");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<PlatformFirmwareSignatureVerification> knownAtomicFlags() {
    return knownFlags;
  }

  private static PlatformFirmwareSignatureVerification initKnownFlag(
      List<String> names, int index, String name) {
    PlatformFirmwareSignatureVerification flag = new PlatformFirmwareSignatureVerification(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private PlatformFirmwareSignatureVerification(int index) {
    super(index);
  }

  public PlatformFirmwareSignatureVerification(PlatformFirmwareSignatureVerification... flags) {
    super(flags);
  }

  public static PlatformFirmwareSignatureVerification fromEncoded(byte[] encoded)
      throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static PlatformFirmwareSignatureVerification fromAsn1(Asn1BitString flags) {
    return new PlatformFirmwareSignatureVerification(Args.notNull(flags, "flags"));
  }

  private PlatformFirmwareSignatureVerification(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "PlatformFirmwareSignatureVerification";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
