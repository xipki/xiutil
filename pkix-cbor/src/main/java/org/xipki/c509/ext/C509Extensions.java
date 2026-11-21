// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.asn1.Asn1Decoder;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.LongPredicate;

/**
 * An ordered list of extensions with distinct IDs.
 * <p>
 * Encoding: a flat array of ID / value pairs, except that a list consisting only of the key
 * usage extension is shortened to a single integer (negative if critical).
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Extensions extends C509CborItem implements Iterable<C509Extension> {

  public static final C509Extensions EMPTY = new C509Extensions(List.of());

  private final List<C509Extension> list;

  public C509Extensions(Collection<C509Extension> extensions) {
    this.list = C509Cbor.frozen(extensions, "extensions");
    Set<Long> seen = new HashSet<>();
    for (C509Extension e : list) {
      if (!seen.add(e.id())) {
        throw new IllegalArgumentException("duplicate extension " +
            ConstExtensionId.describe(e.id()));
      }
    }
  }

  public static C509Extensions of(C509Extension... extensions) {
    return new C509Extensions(Arrays.asList(extensions));
  }

  /**
   * Creates the list in ascending order of the extension IDs.
   */
  public static C509Extensions sorted(Collection<C509Extension> extensions) {
    List<C509Extension> copy = new ArrayList<>(extensions);
    copy.sort(null);
    return new C509Extensions(copy);
  }

  public List<C509Extension> asList() {
    return list;
  }

  public int size() {
    return list.size();
  }

  public boolean isEmpty() {
    return list.isEmpty();
  }

  @Override
  public Iterator<C509Extension> iterator() {
    return list.iterator();
  }

  public long[] ids() {
    return list.stream().mapToLong(C509Extension::id).toArray();
  }

  /**
   * Returns the IDs of the critical extensions, in list order.
   */
  public Set<Long> criticalExtensionIds() {
    return collectIds(Boolean.TRUE);
  }

  /**
   * Returns the IDs of the non-critical extensions, in list order.
   */
  public Set<Long> nonCriticalExtensionIds() {
    return collectIds(Boolean.FALSE);
  }

  /**
   * Returns the IDs of all extensions, in list order.
   */
  public Set<Long> extensionIds() {
    return collectIds(null);
  }

  private Set<Long> collectIds(Boolean critical) {
    Set<Long> ids = new LinkedHashSet<>();
    for (C509Extension e : list) {
      if (critical == null || e.isCritical() == critical) {
        ids.add(e.id());
      }
    }
    return Collections.unmodifiableSet(ids);
  }

  public boolean contains(long id) {
    return get(id) != null;
  }

  public C509Extension get(long id) {
    for (C509Extension e : list) {
      if (e.id() == id) {
        return e;
      }
    }
    return null;
  }

  public <T extends C509ExtnValue> T valueOf(long id, Class<T> type) {
    C509Extension e = get(id);
    return e == null ? null : e.value(type);
  }

  public C509Extensions only(long... ids) {
    return filter(id -> Arrays.stream(ids).anyMatch(x -> x == id));
  }

  public C509Extensions without(long... ids) {
    return filter(id -> Arrays.stream(ids).noneMatch(x -> x == id));
  }

  private C509Extensions filter(LongPredicate keep) {
    List<C509Extension> kept = new ArrayList<>(list.size());
    for (C509Extension e : list) {
      if (keep.test(e.id())) {
        kept.add(e);
      }
    }
    return new C509Extensions(kept);
  }

  // ----- typed shortcuts -----

  public C509KeyUsage keyUsage() {
    return valueOf(ConstExtensionId.keyUsage, C509KeyUsage.class);
  }

  public boolean hasKeyUsage(int mask) {
    C509KeyUsage ku = keyUsage();
    return ku != null && ku.has(mask);
  }

  public boolean hasKeyUsage(C509KeyUsage mask) {
    C509KeyUsage ku = keyUsage();
    return ku != null && ku.has(mask.bits());
  }

  public boolean hasExtKeyUsage(long usage) {
    C509ExtKeyUsageSyntax eku = valueOf(ConstExtensionId.extKeyUsage, C509ExtKeyUsageSyntax.class);
    return eku != null && eku.contains(usage);
  }

  public C509BasicConstraints basicConstraints() {
    return valueOf(ConstExtensionId.basicConstraints, C509BasicConstraints.class);
  }

  public C509AltName subjectAltName() {
    return valueOf(ConstExtensionId.subjectAltName, C509AltName.class);
  }

  public boolean isCA() {
    C509BasicConstraints bc = basicConstraints();
    return bc != null && bc.isCA();
  }

  public byte[] subjectKeyId() {
    C509SubjectKeyIdentifier v =
        valueOf(ConstExtensionId.subjectKeyIdentifier, C509SubjectKeyIdentifier.class);
    return v == null ? null : v.keyId();
  }

  public byte[] authorityKeyId() {
    C509AuthorityKeyIdentifier v =
        valueOf(ConstExtensionId.authorityKeyIdentifier, C509AuthorityKeyIdentifier.class);
    return v == null ? null : v.keyId();
  }

  // ----- codec -----
  public static C509Extensions parse(byte[] encoded) throws CodecException {
    try (ByteArrayCborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return C509Extensions.read(decoder);
    }
  }

  public static C509Extensions read(CborDecoder in) throws CodecException {
    CborType type = in.peekType();
    if (type.isInt()) {
      int signedBits = in.readInt();
      return of(new C509Extension(ConstExtensionId.keyUsage, signedBits < 0,
          new C509KeyUsage(Math.abs(signedBits))));
    }
    if (!type.isArray()) {
      throw new CodecException("Extensions: unexpected CBOR type " + type);
    }
    return new C509Extensions(C509Cbor.readGroups(in, 2, "Extensions", C509Extension::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (list.size() == 1 && list.get(0).id() == ConstExtensionId.keyUsage) {
      C509Extension ku = list.get(0);
      int bits = ku.value(C509KeyUsage.class).bits();
      out.writeLong(ku.isCritical() ? -bits : bits);
    } else {
      C509Cbor.writeGroups(out, 2, list);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    if (list.isEmpty()) {
      out.line("<none>");
    }
    for (C509Extension e : list) {
      out.inline(e);
    }
  }

}
