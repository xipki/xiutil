// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

/**
 * The status of an unsuccessful OCSP response.
 *
 * @author Lijun Liao (xipki)
 */
public enum C509ResponseStatus {

  malformedRequest(1),
  internalError(2),
  tryLater(3),
  sigRequired(5),
  unauthorized(6);

  private final int code;

  C509ResponseStatus(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static C509ResponseStatus ofCode(int code) {
    for (C509ResponseStatus s : values()) {
      if (s.code == code) {
        return s;
      }
    }
    throw new IllegalArgumentException("unknown OCSP response status " + code);
  }

}
