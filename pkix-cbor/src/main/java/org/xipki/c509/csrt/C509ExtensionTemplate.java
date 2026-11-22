// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csrt;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.ext.C509NullExtnValue;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * One extension of the template.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ExtensionTemplate extends C509CborItem {

  private final long id;

  private final boolean optional;

  private final boolean open;

  private final C509ExtnValue value;

  private C509ExtensionTemplate(long id, boolean optional, boolean open, C509ExtnValue value) {
    if (id <= 0) {
      throw new IllegalArgumentException("extension ID must be positive: " + id);
    }
    this.id = id;
    this.optional = optional;
    this.open = open;
    this.value = open ? null : C509Extension.checkValue(id, value);
  }

  /**
   * An extension with a fixed value ({@link C509NullExtnValue#INSTANCE} for extensions without
   * value).
   */
  public static C509ExtensionTemplate fixed(long id, boolean optional, C509ExtnValue value) {
    return new C509ExtensionTemplate(id, optional, false, value);
  }

  /** An extension whose value the requester chooses. */
  public static C509ExtensionTemplate open(long id, boolean optional) {
    return new C509ExtensionTemplate(id, optional, true, null);
  }

  public long id() {
    return id;
  }

  public boolean isOptional() {
    return optional;
  }

  public boolean isOpen() {
    return open;
  }

  public C509ExtnValue value() {
    return value;
  }

  static C509ExtensionTemplate read(CborDecoder in) throws CodecException {
    long id = Math.abs(in.readLong());
    boolean optional = in.readBoolean();
    if (in.peekType().isUndefined()) {
      in.readUndefined();
      return open(id, optional);
    }
    return fixed(id, optional, C509Extension.readValue(id, in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(id);
    out.writeBoolean(optional);
    if (open) {
      out.writeUndefined();
    } else {
      out.writeObject(value);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    String heading = ConstExtensionId.describe(id) + (optional ? " [optional]" : "");
    if (open) {
      out.line(heading + ": requester's choice");
    } else if (value instanceof C509NullExtnValue) {
      out.line(heading);
    } else {
      out.item(heading, value);
    }
  }

}
