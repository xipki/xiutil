// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.util.ReflectiveUtil;
import org.xipki.pkix.pkcs11.P11CryptServiceFactory;
import org.xipki.pkix.pkcs11.P11SignerFactory;
import org.xipki.pkix.pkcs11.P11SystemConf;
import org.xipki.pkix.pkcs12.P12SignerFactory;
import org.xipki.pkix.sign.SignerFactory;
import org.xipki.pkix.sign.SignerFactoryRegister;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.conf.FileOrValue;
import org.xipki.util.misc.CollectionUtil;

import java.io.Closeable;
import java.util.List;

/**
 * Securities.
 * {@link P11CryptServiceFactory}.
 *
 * @author Lijun Liao (xipki)
 */
public class Securities implements Closeable {

  /**
   * Security configuration.
   */
  public static class SecurityConf {

    private int defaultSignerParallelism = 32;

    private FileOrValue pkcs11Conf;

    /**
     * list of classes that implement {@link SignerFactory}
     */
    private List<String> signerFactories;

    public static final SecurityConf DEFAULT;

    static {
      DEFAULT = new SecurityConf();
    }

    public int defaultSignerParallelism() {
      return defaultSignerParallelism;
    }

    public void setDefaultSignerParallelism(int defaultSignerParallelism) {
      this.defaultSignerParallelism = defaultSignerParallelism;
    }

    public FileOrValue pkcs11Conf() {
      return pkcs11Conf;
    }

    public void setPkcs11Conf(FileOrValue pkcs11Conf) {
      this.pkcs11Conf = pkcs11Conf;
    }

    public List<String> signerFactories() {
      return signerFactories;
    }

    public void setSignerFactories(List<String> signerFactories) {
      this.signerFactories = signerFactories;
    }

    public static SecurityConf parse(JsonMap json) throws CodecException {
      SecurityConf ret = new SecurityConf();

      Integer i = json.getInt("defaultSignerParallelism");
      if (i != null) {
        ret.setDefaultSignerParallelism(i);
      }

      ret.setPkcs11Conf(FileOrValue.parse(json.getMap("pkcs11Conf")));
      ret.setSignerFactories(json.getStringList("signerFactories"));

      return ret;
    }

  } // class SecurityConf

  private static final Logger LOG = LoggerFactory.getLogger(Securities.class);

  private P11CryptServiceFactory p11CryptServiceFactory;

  private SecurityFactoryImpl securityFactory;

  public Securities() {
  }

  public SecurityFactory securityFactory() {
    return securityFactory;
  }

  public P11CryptServiceFactory p11CryptServiceFactory() {
    return p11CryptServiceFactory;
  }

  public void init() throws InvalidConfException {
    init(null);
  }

  public void init(SecurityConf conf) throws InvalidConfException {
    if (conf == null) {
      conf = SecurityConf.DEFAULT;
    }

    initSecurityFactory(conf);
  }

  @Override
  public void close() {
    if (p11CryptServiceFactory != null) {
      try {
        p11CryptServiceFactory.close();
      } catch (Throwable th) {
        LOG.error("error while closing P11CryptServiceFactory", th);
      }
      this.p11CryptServiceFactory = null;
    }
  } // method close

  private void initSecurityFactory(SecurityConf conf)
      throws InvalidConfException {
    securityFactory = new SecurityFactoryImpl();

    securityFactory.setDefaultSignerParallelism(conf.defaultSignerParallelism());

    //----- Factories
    SignerFactoryRegister signerFactoryRegister = new SignerFactoryRegister();
    securityFactory.setSignerFactoryRegister(signerFactoryRegister);

    // PKCS#12 (software)
    signerFactoryRegister.registFactory(new P12SignerFactory());

    // PKCS#11
    if (conf.pkcs11Conf() != null) {
      initSecurityPkcs11(conf.pkcs11Conf(), signerFactoryRegister);
    }

    // register additional SignerFactories
    if (CollectionUtil.isNotEmpty(conf.signerFactories())) {
      for (String className : conf.signerFactories()) {
        SignerFactory factory;
        try {
          factory = ReflectiveUtil.newInstance(className);
        } catch (GenerationException ex) {
          throw new InvalidConfException(ex.getMessage(), ex);
        }
        signerFactoryRegister.registFactory(factory);
      }
    }
  } // method initSecurityFactory

  private void initSecurityPkcs11(
      FileOrValue pkcs11Conf, SignerFactoryRegister signerFactoryRegister)
      throws InvalidConfException {
    p11CryptServiceFactory = new P11CryptServiceFactory();

    P11SystemConf pkcs11ConfObj = P11SystemConf.parse(pkcs11Conf);
    p11CryptServiceFactory.setPkcs11Conf(pkcs11ConfObj);
    p11CryptServiceFactory.init();

    P11SignerFactory p11SignerFactory = new P11SignerFactory();
    p11SignerFactory.setP11CryptServiceFactory(p11CryptServiceFactory);
    signerFactoryRegister.registFactory(p11SignerFactory);
  }

}
