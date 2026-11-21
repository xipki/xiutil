// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The policy constraints extension (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * PolicyConstraints = [
 *   requireExplicitPolicy: uint / null,
 *   inhibitPolicyMapping: uint / null,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PolicyConstraints extends C509ExtnValue {

  private final Integer requireExplicitPolicy;

  private final Integer inhibitPolicyMapping;

  public C509PolicyConstraints(Integer requireExplicitPolicy, Integer inhibitPolicyMapping) {
    this.requireExplicitPolicy = checked(requireExplicitPolicy, "requireExplicitPolicy");
    this.inhibitPolicyMapping = checked(inhibitPolicyMapping, "inhibitPolicyMapping");
  }

  private static Integer checked(Integer v, String name) {
    if (v != null && v < 0) {
      throw new IllegalArgumentException(name + " must not be negative");
    }
    return v;
  }

  public Integer requireExplicitPolicy() {
    return requireExplicitPolicy;
  }

  public Integer inhibitPolicyMapping() {
    return inhibitPolicyMapping;
  }

  public static C509PolicyConstraints read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    Integer require = C509Cbor.orNull(in, CborDecoder::readInt);
    Integer inhibit = C509Cbor.orNull(in, CborDecoder::readInt);
    return new C509PolicyConstraints(require, inhibit);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    out.writeIntObj(requireExplicitPolicy);
    out.writeIntObj(inhibitPolicyMapping);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("require explicit policy", requireExplicitPolicy)
        .kv("inhibit policy mapping", inhibitPolicyMapping);
  }

  @Override
  public String label() {
    return "Policy Constraints";
  }

}
