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
 * The CRL distribution points (and freshest CRL) extension. A single point that consists of
 * exactly one URI is encoded as a bare text string.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CRLDistributionPoints extends C509ExtnValue {

  private final List<C509DistributionPointName> points;

  public C509CRLDistributionPoints(List<C509DistributionPointName> points) {
    this.points = C509Cbor.nonEmpty(C509Cbor.frozen(points, "points"), "points");
  }

  public static C509CRLDistributionPoints of(C509DistributionPointName... points) {
    return new C509CRLDistributionPoints(List.of(points));
  }

  public List<C509DistributionPointName> points() {
    return points;
  }

  public static C509CRLDistributionPoints read(CborDecoder in) throws CodecException {
    if (in.peekType().isTextString()) {
      return of(C509DistributionPointName.of(in.readTextString()));
    }
    return new C509CRLDistributionPoints(C509Cbor.readArray(in, C509DistributionPointName::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (points.size() == 1 && points.get(0).isPlainUri()) {
      out.writeTextString(points.get(0).uris().get(0));
    } else {
      C509Cbor.writeGroups(out, 1, points);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    for (C509DistributionPointName p : points) {
      out.item("distribution point", p);
    }
  }

  @Override
  public String label() {
    return "CRL Distribution Points";
  }

}
