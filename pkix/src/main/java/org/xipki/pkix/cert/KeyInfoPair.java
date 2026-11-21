// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.codec.c509.C509SubjectPublicKeyInfo;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;

/**
 * Key Info Pair.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class KeyInfoPair {

  private final PrivateKeyInfo _private;

  private KeyInfoPair(PrivateKeyInfo _private) {
    this._private = Args.notNull(_private, "_private");
  }

  public PrivateKeyInfo getPrivate() {
    return _private;
  }

  /**
   * C509-based Key Info Pair.
   *
   * @author Lijun Liao (xipki)
   */
  public static class C509 extends KeyInfoPair {

    private final C509SubjectPublicKeyInfo _public;

    public C509(KeyPair keyPair) throws CodecException, InvalidKeySpecException {
      super(PrivateKeyInfo.fromPrivateKey(Args.notNull(keyPair, "keyPair").getPrivate()));
      this._public = new C509SubjectPublicKeyInfo(
          C509SubjectPublicKey.fromSubjectPublicKeyInfo(
            SubjectPublicKeyInfo.fromPublicKey(keyPair.getPublic())));
    }

    public C509(C509SubjectPublicKey _public, PrivateKeyInfo _private) {
      super(_private);
      this._public = new C509SubjectPublicKeyInfo(Args.notNull(_public, "_public"));
    }

    public C509(C509SubjectPublicKeyInfo _public, PrivateKeyInfo _private) {
      super(_private);
      this._public = Args.notNull(_public, "_public");
    }

    public C509SubjectPublicKeyInfo getPublic() {
      return _public;
    }

  }

  /**
   * X509-based Key Info Pair.
   *
   * @author Lijun Liao (xipki)
   */
  public static class X509 extends KeyInfoPair {

    private final SubjectPublicKeyInfo _public;

    public X509(KeyPair keyPair) throws CodecException {
      super(PrivateKeyInfo.fromPrivateKey(Args.notNull(keyPair, "keyPair").getPrivate()));
      this._public = SubjectPublicKeyInfo.fromPublicKey(keyPair.getPublic());
    }

    public X509(SubjectPublicKeyInfo _public, PrivateKeyInfo _private) {
      super(_private);
      this._public = Args.notNull(_public, "_public");
    }

    public SubjectPublicKeyInfo getPublic() {
      return _public;
    }

  }

}
