// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509CborItem;

/**
 * Base class of all attribute values.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509AttrValue extends C509CborItem {

  public abstract String label();

  @Override
  protected String getTitle() {
    return label();
  }

}
