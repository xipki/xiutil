// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.key;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstPrivateKeyType;
import org.xipki.codec.util.Args;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborMap;
import org.xipki.codec.exception.CodecException;

import java.util.Map;

/**
 * A C509 private key:
 * <pre>
 * C509PrivateKey = [
 *   C509PrivateKeyType: int,
 *   subjectPrivateKeyAlgorithm: AlgorithmIdentifier,
 *   subjectPrivateKey: any,
 * ]
 * </pre>
 * For the type {@link ConstPrivateKeyType#asymmetricKeyPackage}, the subjectPrivateKey is the
 * value of the PrivateKey OCTET STRING of RFC 5958 as a byte string. For the type
 * {@link ConstPrivateKeyType#coseKey} it is kept as a {@link CborMap}, so that it is encoded
 * deterministically. For other types it is kept as {@link CborEncodedItem}. The text form never
 * shows the private key.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PrivateKey extends C509CborItem {

  private final int type;

  private final int algorithm;

  private final byte[] x509PrivateKey;

  private final CborMap cosePrivateKey;

  private final CborEncodedItem rawPrivateKey;

  /**
   * @param type       the private key type, see {@link ConstPrivateKeyType}.
   * @param algorithm  the private key algorithm.
   * @param privateKey the private key: a byte[] for the type
   *                   {@link ConstPrivateKeyType#asymmetricKeyPackage}, a Map for the type
   *                   {@link ConstPrivateKeyType#coseKey} (its maps, also nested ones, are
   *                   converted to {@link CborMap}), otherwise a {@link CborEncodedItem}.
   */
  private C509PrivateKey(int type, int algorithm, Object privateKey) {
    this.type = type;
    this.algorithm = algorithm;
    Args.notNull(privateKey, "privateKey");
    if (type == ConstPrivateKeyType.asymmetricKeyPackage) {
      if (!(privateKey instanceof byte[])) {
        throw new IllegalArgumentException("privateKey of type "
            + ConstPrivateKeyType.describe(type) + " must be byte[]");
      }
      this.x509PrivateKey = ((byte[]) privateKey).clone();
      this.cosePrivateKey = null;
      this.rawPrivateKey = null;
    } else if (type == ConstPrivateKeyType.coseKey) {
      if (!(privateKey instanceof Map)) {
        throw new IllegalArgumentException("privateKey of type "
            + ConstPrivateKeyType.describe(type) + " must be a Map");
      }
      try {
        this.cosePrivateKey = (CborMap) CborMap.deepSorted(privateKey);
      } catch (CodecException e) {
        throw new IllegalArgumentException("invalid privateKey: " + e.getMessage(), e);
      }
      this.x509PrivateKey = null;
      this.rawPrivateKey = null;
    } else {
      if (!(privateKey instanceof CborEncodedItem)) {
        throw new IllegalArgumentException("privateKey of type "
            + ConstPrivateKeyType.describe(type) + " must be a CborEncodedItem");
      }
      this.rawPrivateKey = (CborEncodedItem) privateKey;
      this.x509PrivateKey = null;
      this.cosePrivateKey = null;
    }
  }

  public static C509PrivateKey ofAsymmetricKeyPackage(int algorithm, byte[] privateKey) {
    return new C509PrivateKey(ConstPrivateKeyType.asymmetricKeyPackage,
        algorithm, privateKey);
  }

  public static C509PrivateKey ofCoseKey(int algorithm, Map<?, ?> privateKey) {
    return new C509PrivateKey(ConstPrivateKeyType.coseKey,
        algorithm, privateKey);
  }

  /**
   * Creates a private key of a type other than {@link ConstPrivateKeyType#asymmetricKeyPackage}
   * and {@link ConstPrivateKeyType#coseKey}.
   *
   * @throws IllegalArgumentException if the type is asymmetricKeyPackage or coseKey.
   */
  public static C509PrivateKey ofRaw(int type, int algorithm, CborEncodedItem privateKey) {
    if (type == ConstPrivateKeyType.asymmetricKeyPackage
        || type == ConstPrivateKeyType.coseKey) {
      throw new IllegalArgumentException("type " + ConstPrivateKeyType.describe(type)
          + " has a dedicated form");
    }
    return new C509PrivateKey(type, algorithm, Args.notNull(privateKey, "privateKey"));
  }

  /**
   * Converts an ASN.1 PrivateKeyInfo (OneAsymmetricKey of RFC 5958) to a C509 private key of
   * type {@link ConstPrivateKeyType#asymmetricKeyPackage}. The optional attributes and public
   * key of the PrivateKeyInfo have no counterpart in C509PrivateKey and are dropped.
   */
  public static C509PrivateKey fromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) {
    Args.notNull(privateKeyInfo, "privateKeyInfo");
    Integer algorithm = ConstPublicKeyAlgorithm.codeForX509AlgId(
        privateKeyInfo.getPrivateKeyAlgorithm().getEncoded());
    if (algorithm == null) {
      throw new IllegalArgumentException("unsupported key algorithm " +
          privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());
    }
    return new C509PrivateKey(ConstPrivateKeyType.asymmetricKeyPackage, algorithm,
        privateKeyInfo.privateKey());
  }

  /**
   * Converts this private key to an ASN.1 PrivateKeyInfo (version v1, without attributes).
   *
   * @throws CodecException if the type is not {@link ConstPrivateKeyType#asymmetricKeyPackage},
   *         or the algorithm cannot be converted.
   */
  public PrivateKeyInfo toPrivateKeyInfo() throws CodecException {
    if (type != ConstPrivateKeyType.asymmetricKeyPackage) {
      throw new CodecException("cannot convert private key of type "
          + ConstPrivateKeyType.describe(type) + " to PrivateKeyInfo");
    }
    return new PrivateKeyInfo(
        ConstPublicKeyAlgorithm.getX509AlgorithmIdentifier(algorithm), x509PrivateKey);
  }

  public long type() {
    return type;
  }

  public int algorithm() {
    return algorithm;
  }

  /**
   * The private key: a copy of the byte[] for the type
   * {@link ConstPrivateKeyType#asymmetricKeyPackage}, an unmodifiable {@link CborMap} for the
   * type {@link ConstPrivateKeyType#coseKey}, otherwise a {@link CborEncodedItem}.
   */
  public Object privateKey() {
    return x509PrivateKey != null ? x509PrivateKey.clone()
        : cosePrivateKey != null ? cosePrivateKey : rawPrivateKey;
  }

  public static C509PrivateKey parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509PrivateKey::read);
  }

  public static C509PrivateKey read(CborDecoder in) throws CodecException {
    in.readArrayLength(3);
    int type = in.readInt();
    int algorithm = in.readInt();
    Object privateKey;
    if (type == ConstPrivateKeyType.asymmetricKeyPackage) {
      privateKey = in.readByteString();
    } else if (type == ConstPrivateKeyType.coseKey) {
      privateKey = in.readNext();
      if (!(privateKey instanceof Map)) {
        throw new CodecException("private key of type " + ConstPrivateKeyType.describe(type)
            + ": expected a map");
      }
    } else {
      privateKey = in.readEncodedItem();
    }
    return new C509PrivateKey(type, algorithm, privateKey);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(3);
    out.writeInt(type);
    out.writeInt(algorithm);
    if (x509PrivateKey != null) {
      out.writeByteString(x509PrivateKey);
    } else if (cosePrivateKey != null) {
      out.writeAnyObject(cosePrivateKey);
    } else {
      rawPrivateKey.encode(out);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("type", ConstPrivateKeyType.describe(type))
        .kv("algorithm", ConstPublicKeyAlgorithm.describe(algorithm))
        .kv("privateKey", "******");
  }

}
