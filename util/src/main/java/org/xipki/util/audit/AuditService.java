// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.audit;

import org.xipki.codec.util.ConfPairs;
import org.xipki.codec.exception.InvalidConfException;

/**
 * Audit Service interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface AuditService {

  int AUDIT_EVENT = 1;

  int PCI_AUDIT_EVENT = 2;

  /**
   * Initializes the audit service.
   * @param conf the configuration.
   * @param basedir the base directory, against which relative paths are resolved. May be
   *                {@code null}.
   * @throws InvalidConfException if the configuration is invalid.
   */
  default void init(String conf, String basedir) throws InvalidConfException {
    init(new ConfPairs(conf), basedir);
  }

  /**
   * Initializes the audit service.
   * @param conf the configuration.
   * @param basedir the base directory, against which relative paths are resolved. May be
   *                {@code null}.
   * @throws InvalidConfException if the configuration is invalid.
   */
  void init(ConfPairs conf, String basedir) throws InvalidConfException;

  /**
   * Log audit event.
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(AuditEvent event);

  /**
   * Log PCI audit event.
   *
   * @param event
   *          Audit event. Must not be {@code null}-
   */
  void logEvent(PciAuditEvent event);

  void close() throws Exception;

}
