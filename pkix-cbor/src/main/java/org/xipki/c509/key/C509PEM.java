// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.key;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.cert.CoseC509;
import org.xipki.codec.util.Args;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * A private key with its optional certificate (chain):
 * <pre>
 * C509PEM = [
 *   C509PrivateKey,
 *   COSE_C509 / null,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PEM extends C509CborItem {

  private final C509PrivateKey privateKey;

  private final CoseC509 certificates;

  /**
   * @param privateKey   the private key.
   * @param certificates the certificate (chain), or null.
   */
  public C509PEM(C509PrivateKey privateKey, CoseC509 certificates) {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.certificates = certificates;
  }

  /**
   * Creates a C509PEM from an ASN.1 PrivateKeyInfo, without certificates.
   *
   * @see C509PrivateKey#fromPrivateKeyInfo(PrivateKeyInfo)
   */
  public static C509PEM fromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) {
    return fromPrivateKeyInfo(privateKeyInfo, null);
  }

  /**
   * Creates a C509PEM from an ASN.1 PrivateKeyInfo.
   *
   * @param privateKeyInfo the private key.
   * @param certificates   the certificate (chain), or null.
   * @see C509PrivateKey#fromPrivateKeyInfo(PrivateKeyInfo)
   */
  public static C509PEM fromPrivateKeyInfo(
      PrivateKeyInfo privateKeyInfo,
      CoseC509 certificates) {
    return new C509PEM(C509PrivateKey.fromPrivateKeyInfo(privateKeyInfo), certificates);
  }

  /**
   * Converts the private key to an ASN.1 PrivateKeyInfo.
   *
   * @see C509PrivateKey#toPrivateKeyInfo()
   */
  public PrivateKeyInfo toPrivateKeyInfo() throws CodecException {
    return privateKey.toPrivateKeyInfo();
  }

  public C509PrivateKey privateKey() {
    return privateKey;
  }

  /** The certificate (chain), or null. */
  public CoseC509 certificates() {
    return certificates;
  }

  public static C509PEM parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509PEM::read);
  }

  public static C509PEM read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    C509PrivateKey privateKey = C509PrivateKey.read(in);
    return new C509PEM(privateKey, C509Cbor.orNull(in, CoseC509::read));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    privateKey.encode(out);
    if (certificates == null) {
      out.writeNull();
    } else {
      certificates.encode(out);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    out.item("privateKey", privateKey).item("certificates", certificates);
  }

}
