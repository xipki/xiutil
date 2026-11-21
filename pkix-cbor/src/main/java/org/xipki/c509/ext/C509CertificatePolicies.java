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
 * The certificate policies extension (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * PolicyIdentifier = int / ~oid
 * PolicyQualifierInfo = (
 *   policyQualifierId: int / ~oid,
 *   qualifier: text,
 * )
 * CertificatePolicies = [
 *   + ( PolicyIdentifier, [ * PolicyQualifierInfo ] )
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificatePolicies extends C509ExtnValue {

  /**
   * A policy identifier with optional qualifiers.
   */
  public static final class Policy extends C509CborItem {

    private final long id;

    private final List<C509PolicyQualifierInfo> qualifiers;

    public Policy(long id, List<C509PolicyQualifierInfo> qualifiers) {
      this.id = id;
      this.qualifiers = C509Cbor.frozen(qualifiers == null ? List.of() : qualifiers, "qualifiers");
    }

    public static Policy of(long id, C509PolicyQualifierInfo... qualifiers) {
      return new Policy(id, List.of(qualifiers));
    }

    public long id() {
      return id;
    }

    public List<C509PolicyQualifierInfo> qualifiers() {
      return qualifiers;
    }

    static Policy read(CborDecoder in) throws CodecException {
      long id = in.readLong();
      return new Policy(id,
          C509Cbor.readGroups(in, 2, "PolicyQualifiers", C509PolicyQualifierInfo::read));
    }

    @Override
    protected void writeTo(CborEncoder out) throws CodecException {
      out.writeLong(id);
      C509Cbor.writeGroups(out, 2, qualifiers);
    }

    @Override
    protected void render(C509TextTree out) {
      C509TextTree sub = out.nest(ConstCertificatePolicy.describe(id));
      qualifiers.forEach(sub::inline);
    }

  }

  private final List<Policy> policies;

  public C509CertificatePolicies(List<Policy> policies) {
    this.policies = C509Cbor.nonEmpty(C509Cbor.frozen(policies, "policies"), "policies");
  }

  public static C509CertificatePolicies of(Policy... policies) {
    return new C509CertificatePolicies(List.of(policies));
  }

  public List<Policy> policies() {
    return policies;
  }

  public static C509CertificatePolicies read(CborDecoder in) throws CodecException {
    return new C509CertificatePolicies(
        C509Cbor.readGroups(in, 2, "CertificatePolicies", Policy::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, policies);
  }

  @Override
  protected void render(C509TextTree out) {
    policies.forEach(out::inline);
  }

  @Override
  public String label() {
    return "Certificate Policies";
  }

}
