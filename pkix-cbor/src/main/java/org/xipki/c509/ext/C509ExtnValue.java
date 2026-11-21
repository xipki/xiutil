// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509CborItem;

/**
 * Base class of all extension values.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509ExtnValue extends C509CborItem {

  /**
   * Returns a short human-readable name of the value type.
   */
  public abstract String label();

  @Override
  protected String getTitle() {
    return label();
  }

}
