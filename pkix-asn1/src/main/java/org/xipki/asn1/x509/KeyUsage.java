// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

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
 * The KeyUsage object.
 * <pre>
 *    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 *
 *    KeyUsage ::= BIT STRING {
 *         digitalSignature        (0),
 *         nonRepudiation          (1),
 *         keyEncipherment         (2),
 *         dataEncipherment        (3),
 *         keyAgreement            (4),
 *         keyCertSign             (5),
 *         cRLSign                 (6),
 *         encipherOnly            (7),
 *         decipherOnly            (8) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class KeyUsage extends FlagsBitString {

  private static final Set<KeyUsage> knownFlags = new HashSet<>(9);
  private static final List<String> names;

  public static final KeyUsage digitalSignature;
  public static final KeyUsage nonRepudiation;
  public static final KeyUsage keyEncipherment;
  public static final KeyUsage dataEncipherment;
  public static final KeyUsage keyAgreement;
  public static final KeyUsage keyCertSign;
  public static final KeyUsage cRLSign;
  public static final KeyUsage encipherOnly;
  public static final KeyUsage decipherOnly;

  static {
    List<String> names0 = new ArrayList<>(9);
    digitalSignature = initKnownFlag(names0, 0, "digitalSignature");
    nonRepudiation   = initKnownFlag(names0, 1, "nonRepudiation");
    keyEncipherment  = initKnownFlag(names0, 2, "keyEncipherment");
    dataEncipherment = initKnownFlag(names0, 3, "dataEncipherment");
    keyAgreement     = initKnownFlag(names0, 4, "keyAgreement");
    keyCertSign      = initKnownFlag(names0, 5, "keyCertSign");
    cRLSign          = initKnownFlag(names0, 6, "cRLSign");
    encipherOnly     = initKnownFlag(names0, 7, "encipherOnly");
    decipherOnly     = initKnownFlag(names0, 8, "decipherOnly");
    names = Collections.unmodifiableList(names0);
  }

  public static Set<KeyUsage> knownAtomicFlags() {
    return knownFlags;
  }

  private static KeyUsage initKnownFlag(List<String> names, int index, String name) {
    KeyUsage flag = new KeyUsage(index);
    knownFlags.add(flag);
    names.add(name);
    return flag;
  }

  private KeyUsage(int index) {
    super(index);
  }

  public KeyUsage(KeyUsage... flags) {
    super(flags);
  }

  public KeyUsage(List<KeyUsage> flags) {
    super(flags);
  }

  public static KeyUsage fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1BitString.fromEncoded(encoded));
  }

  public static KeyUsage fromAsn1(Asn1BitString flags) {
    return new KeyUsage(Args.notNull(flags, "flags"));
  }

  private KeyUsage(Asn1BitString flags) {
    super(flags);
  }

  @Override
  protected String getTitle() {
    return "KeyUsage";
  }

  @Override
  protected List<String> getFlagNames() {
    return names;
  }

}
