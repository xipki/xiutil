// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.exception;

/**
 * Exception of the PKIX processing, e.g. CMS, CMP and OCSP.
 *
 * @author Lijun Liao (xipki)
 */
public class PkixException extends Exception {

  public PkixException(String message) {
    super(message);
  }

  public PkixException(String message, Throwable cause) {
    super(message, cause);
  }

  public PkixException(Throwable cause) {
    super(cause);
  }

}
