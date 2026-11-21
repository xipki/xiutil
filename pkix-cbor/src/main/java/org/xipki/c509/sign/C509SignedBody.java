// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.sign;

import org.xipki.c509.base.C509CborItem;

/**
 * The to-be-signed part of a signed structure. Its encoding is the sequence of its fields
 * without an enclosing array header; this is exactly what gets signed.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509SignedBody extends C509CborItem {

  /** Number of CBOR data items written by {@link #encode}. */
  protected abstract int fieldCount();

  /** The C509 signature algorithm identifier. */
  public abstract int signatureAlgorithm();

}
