// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <pre>
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Extensions extends Extension.Seq1 {

  public static class Generator {

    private final Map<Asn1Oid, Extension> idExensionMap = new HashMap<>();

    private final List<Asn1Oid> ids = new LinkedList<>();

    public Generator() {
    }

    public void addExtension(Extension extension) throws GenerationException {
      Args.notNull(extension, "extension");
      Asn1Oid oid = extension.getExtnId();
      boolean exists = ids.contains(oid);
      if (exists) {
        throw new GenerationException("extension " + oid + " exists");
      }

      idExensionMap.put(oid, extension);
      ids.add(oid);
    }

    public Extension replaceExtension(Extension extension) {
      Args.notNull(extension, "extension");
      Asn1Oid oid = extension.getExtnId();
      boolean exists = ids.contains(oid);
      Extension oldEx = exists ? idExensionMap.remove(oid) : null;

      idExensionMap.put(oid, extension);
      if (!exists) {
        ids.add(oid);
      }

      return oldEx;
    }

    public Extension removeExtension(Asn1Oid extensionId) {
      Args.notNull(extensionId, "extensionId");
      boolean exists = ids.remove(extensionId);
      return exists ? idExensionMap.remove(extensionId) : null;
    }

    public Extension getExtension(Asn1Oid extensionId) {
      return idExensionMap.get(extensionId);
    }

    public boolean hasExtensions() {
      return !ids.isEmpty();
    }

    public boolean hasExtension(Asn1Oid extensionId) {
      return ids.contains(extensionId);
    }

    public Extensions build() throws CodecException {
      if (ids.isEmpty()) {
        throw new CodecException("no extension is present");
      }

      Extension[] extns = new Extension[ids.size()];
      int i = 0;
      for (Asn1Oid oid : ids) {
        extns[i++] = idExensionMap.get(oid);
      }
      return new Extensions(extns);
    }
  }

  private final Set<Asn1Oid> extenionIds;

  private final Set<Asn1Oid> critialExtenionIds;

  private final Set<Asn1Oid> nonCritialExtenionIds;

  public static Extensions fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = seq.size();
    Args.positive(size, "sequence size");

    Set<Asn1Oid> oids = new HashSet<>();
    Extension[] value = new Extension[size];
    for (int i = 0; i < size; i++) {
      value[i] = Extension.fromAsn1(seq.getSequenceAt(i));
      Asn1Oid oid = value[i].getExtnId();
      if (!oids.add(oid)) {
        throw new CodecException("duplicated extension " + oid);
      }
    }

    // check the duplication
    return new Extensions(value);
  }

  public static Extensions fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public Extensions(List<Extension> extensions) {
    this(Args.notEmptyAndNoNullElements(extensions, "extensions").toArray(new Extension[0]));
  }

  /**
   * Base Constructor
   *
   * @param extensions an array of extensions.
   */
  public Extensions(Extension... extensions) {
    super(extensions);

    int size = entries.size();
    HashSet<Asn1Oid> oids = new HashSet<>(size);
    HashSet<Asn1Oid> criticalOids = new HashSet<>(size);
    HashSet<Asn1Oid> nonCriticalOids = new HashSet<>(size);
    for (Extension extn : this.entries) {
      Asn1Oid oid = extn.getExtnId();
      if(!oids.add(oid)) {
        throw new IllegalArgumentException("duplicated extension " + oid);
      }

      (extn.isCritical() ? criticalOids : nonCriticalOids).add(extn.getExtnId());
    }
    this.extenionIds = Collections.unmodifiableSet(oids);
    this.nonCritialExtenionIds = Collections.unmodifiableSet(nonCriticalOids);
    this.critialExtenionIds = Collections.unmodifiableSet(criticalOids);
  }

  /**
   * return an Enumeration of the extension field's object ids.
   */
  public Set<Asn1Oid> getExtensionIds() {
    return extenionIds;
  }

  /**
   * return the extension represented by the object identifier
   * passed in.
   *
   * @return the extension if it's present, null otherwise.
   */
  public Extension getExtension(Asn1Oid oid) {
    if (extenionIds.contains(oid)) {
      for (Extension extn : entries) {
        if (extn.getExtnId().equals(oid)) {
          return extn;
        }
      }
    }
    return null;
  }

  public Asn1OctetString getExtensionValue(Asn1Oid oid) {
    Extension ext = getExtension(oid);
    return ext == null ? null : ext.getExtnValue();
  }

  public byte[] extensionValue(Asn1Oid oid) {
    Extension ext = getExtension(oid);
    return ext == null ? null : ext.getExtnValue().getOctets();
  }

  public Set<Asn1Oid> getNonCriticalExtensionIds() {
    return nonCritialExtenionIds;
  }

  public Set<Asn1Oid> getCriticalExtensionIds() {
    return critialExtenionIds;
  }

  @Override
  protected String getTitle() {
    return "Extensions";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    for (Extension extension : entries) {
      extension.toString(buf, indentLevel).append("\n");
    }
    buf.deleteCharAt(buf.length() - 1);
    return buf;
  }
}
