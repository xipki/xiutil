// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * The OCSP request extension with the preferred signature algorithms
 * (draft-liao-cose-c509-revocation-01, Section 7.5.2.13).
 *
 * <pre>
 * PreferredSignatureAlgorithm = (
 *   sigIdentifier        : IntAlgorithmIdentifier,
 *   pubKeyAlgIdentifiers : [ 2* IntAlgorithmIdentifier ]
 *                          / IntAlgorithmIdentifier
 *                          / null,
 * )
 * PreferredSignatureAlgorithms = [ + PreferredSignatureAlgorithm ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PreferredSignatureAlgorithms extends C509ExtnValue {

  private final List<C509PreferredSignatureAlgorithm> entries;

  public C509PreferredSignatureAlgorithms(List<C509PreferredSignatureAlgorithm> entries) {
    this.entries = C509Cbor.nonEmpty(C509Cbor.frozen(entries, "entries"), "entries");
  }

  public static C509PreferredSignatureAlgorithms of(C509PreferredSignatureAlgorithm... entries) {
    return new C509PreferredSignatureAlgorithms(List.of(entries));
  }

  public List<C509PreferredSignatureAlgorithm> entries() {
    return entries;
  }

  public static C509PreferredSignatureAlgorithms read(CborDecoder in) throws CodecException {
    List<C509PreferredSignatureAlgorithm> entries = C509Cbor.readGroups(in, 2,
        "PreferredSignatureAlgorithms", C509PreferredSignatureAlgorithm::read);
    if (entries.isEmpty()) {
      throw new CodecException("PreferredSignatureAlgorithms must not be empty");
    }
    return new C509PreferredSignatureAlgorithms(entries);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    C509Cbor.writeGroups(out, 2, entries);
  }

  @Override
  protected void render(C509TextTree out) {
    entries.forEach(out::inline);
  }

  @Override
  public String label() {
    return "Preferred Signature Algorithms";
  }

}
