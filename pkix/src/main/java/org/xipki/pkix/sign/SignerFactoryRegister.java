// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.Args;
import org.xipki.pkix.SecurityFactory;
import org.xipki.pkix.cert.X509Cert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Signer Factory Register.
 * {@link ConcurrentSigner}.
 *
 * @author Lijun Liao (xipki)
 */
public class SignerFactoryRegister {

  private static final Logger LOG = LoggerFactory.getLogger(SignerFactoryRegister.class);

  private volatile List<SignerFactory> factories = new ArrayList<>();

  public SignerFactoryRegister() {
  }

  /**
   * Retrieves the types of supported signers.
   * @return lower-case types of supported signers, never {@code null}.
   */
  public Set<String> supportedSignerTypes() {
    Set<String> types = new HashSet<>();
    for (SignerFactory service : factories) {
      types.addAll(service.getSupportedSignerTypes());
    }
    return Collections.unmodifiableSet(types);
  }

  public void registFactory(SignerFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("registFactory invoked with null.");
      return;
    }

    boolean replaced = factories.remove(factory);
    factories.add(factory);

    String action = replaced ? "replaced" : "added";
    LOG.info("{} SignerFactory binding for {}", action, factory);
  }

  public void unregistFactory(SignerFactory factory) {
    //might be null if dependency is optional
    if (factory == null) {
      LOG.info("unregistFactory invoked with null.");
      return;
    }

    if (factories.remove(factory)) {
      LOG.info("removed SignerFactory binding for {}", factory);
    } else {
      LOG.info("no SignerFactory binding found to remove for '{}'", factory);
    }
  }

  /**
   * Creates a new {@link ConcurrentSigner}.
   *
   * @param securityFactory
   *          Security factory. Must not be {@code null}.
   * @param type
   *          Type of the signer. Must not be {@code null}.
   * @param conf
   *          Configuration. Must not be {@code null}.
   * @param certificateChain
   *          Certificate chain. Could be {@code null}-
   * @return new signer.
   * @throws GenerationException
   *           If signer could not be created.
   */
  public ConcurrentSigner newSigner(
      SecurityFactory securityFactory, String type, SignerConf conf, X509Cert[] certificateChain)
      throws GenerationException {
    Args.notBlank(type, "type");

    for (SignerFactory service : factories) {
      if (service.canCreateSigner(type)) {
        return service.newSigner(securityFactory, type, conf, certificateChain);
      }
    }

    throw new GenerationException("could not find Factory to create Signer of type " + type);
  }

}
