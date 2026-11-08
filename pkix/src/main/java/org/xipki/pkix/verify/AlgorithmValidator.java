// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Algorithm Validator.
 *
 * @author Lijun Liao (xipki)
 */
public class AlgorithmValidator {

  private static final Logger LOG = LoggerFactory.getLogger(AlgorithmValidator.class);

  public static final AlgorithmValidator INSTANCE;

  private final Set<SignAlgo> algos;

  static {
    List<SignAlgo> secureAlgos = new ArrayList<>(SignAlgo.values().length);
    for (SignAlgo m : SignAlgo.values()) {
      if (m.hashAlgo() != HashAlgo.SHA1) {
        secureAlgos.add(m);
      }
    }
    INSTANCE = new AlgorithmValidator(secureAlgos);
  }

  public static AlgorithmValidator buildAlgorithmValidator(Collection<String> algoNames)
      throws NoSuchAlgorithmException {
    Set<SignAlgo> algos = new HashSet<>();
    for (String algoName : algoNames) {
      SignAlgo sa;
      try {
        sa = SignAlgo.ofName(algoName);
      } catch (NoSuchAlgorithmException ex) {
        LOG.warn("algorithm is not supported {}, ignore it", algoName);
        continue;
      }

      algos.add(sa);
    }

    if (algos.isEmpty()) {
      throw new NoSuchAlgorithmException("none of the signature algorithms "
          + algoNames + " are supported");
    }

    return new AlgorithmValidator(algos);
  }

  /**
   * constructor.
   * @param algos
   *        algorithms that can be accepted. <code>null</code> or empty to
   *        accept all algorithms
   */
  public AlgorithmValidator(Collection<SignAlgo> algos) {
    this.algos = Set.copyOf(algos);
  }

  public boolean isAlgorithmPermitted(AlgorithmIdentifier algId) {
    if (algos.isEmpty()) {
      return true;
    }

    SignAlgo algo;
    try {
      algo = SignAlgo.ofAlgorithmIdentifier(Args.notNull(algId, "algId"));
    } catch (NoSuchAlgorithmException ex) {
      return false;
    }

    return algos.contains(algo);
  }

  public boolean isAlgorithmPermitted(SignAlgo algo) {
    return algos.contains(Args.notNull(algo, "algo"));
  }

}
