// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstCertificatePolicy;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The policy mappings extension: a flat array of issuer / subject policy pairs.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PolicyMappings extends C509ExtnValue {

  /**
   * One issuer domain policy mapped to one subject domain policy.
   */
  public static final class Mapping extends C509CborItem {

    private final long issuerPolicy;

    private final long subjectPolicy;

    public Mapping(long issuerPolicy, long subjectPolicy) {
      this.issuerPolicy = issuerPolicy;
      this.subjectPolicy = subjectPolicy;
    }

    public long issuerPolicy() {
      return issuerPolicy;
    }

    public long subjectPolicy() {
      return subjectPolicy;
    }

    static Mapping read(CborDecoder in) throws CodecException {
      return new Mapping(in.readLong(), in.readLong());
    }

    @Override
    protected void writeTo(CborEncoder out) throws CodecException {
      out.writeLong(issuerPolicy);
      out.writeLong(subjectPolicy);
    }

    @Override
    protected void render(C509TextTree out) {
      out.line(ConstCertificatePolicy.describe(issuerPolicy) + " -> "
          + ConstCertificatePolicy.describe(subjectPolicy));
    }

  }

  private final List<Mapping> mappings;

  public C509PolicyMappings(List<Mapping> mappings) {
    this.mappings = C509Cbor.nonEmpty(C509Cbor.frozen(mappings, "mappings"), "mappings");
  }

  public static C509PolicyMappings of(Mapping... mappings) {
    return new C509PolicyMappings(List.of(mappings));
  }

  public List<Mapping> mappings() {
    return mappings;
  }

  public static C509PolicyMappings read(CborDecoder in) throws CodecException {
    return new C509PolicyMappings(C509Cbor.readGroups(in, 2, "PolicyMappings", Mapping::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, mappings);
  }

  @Override
  protected void render(C509TextTree out) {
    mappings.forEach(out::inline);
  }

  @Override
  public String label() {
    return "Policy Mappings";
  }

}
