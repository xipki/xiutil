// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * The authority key identifier extension (draft-ietf-cose-cbor-encoded-cert-21,
 * Section 3.3): either a bare key identifier, or an array with the key identifier, issuer and
 * serial number.
 *
 * <pre>
 * KeyIdentifierArray = [
 *   keyIdentifier: KeyIdentifier,
 *   authorityCertIssuer: GeneralNames,
 *   authorityCertSerialNumber: CertificateSerialNumber,
 * ]
 * AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509AuthorityKeyIdentifier extends C509ExtnValue {

  private final byte[] keyId;

  private final C509GeneralNames issuer;

  private final BigInteger serialNumber;

  private C509AuthorityKeyIdentifier(
      byte[] keyId, C509GeneralNames issuer, BigInteger serialNumber) {
    this.keyId = C509Cbor.copy(keyId);
    this.issuer = issuer;
    this.serialNumber = serialNumber;
  }

  public static C509AuthorityKeyIdentifier ofKeyId(byte[] keyId) {
    if (keyId == null) {
      throw new IllegalArgumentException("keyId must not be null");
    }
    return new C509AuthorityKeyIdentifier(keyId, null, null);
  }

  /**
   * @param keyId        the key identifier, may be null.
   * @param issuer       the issuer of the authority certificate.
   * @param serialNumber the serial number of the authority certificate.
   */
  public static C509AuthorityKeyIdentifier ofIssuerAndSerial(
      byte[] keyId, C509GeneralNames issuer,
      BigInteger serialNumber) {
    if (issuer == null || serialNumber == null || serialNumber.signum() < 0) {
      throw new IllegalArgumentException("issuer and non-negative serialNumber are required");
    }
    return new C509AuthorityKeyIdentifier(keyId, issuer, serialNumber);
  }

  public byte[] keyId() {
    return C509Cbor.copy(keyId);
  }

  public C509GeneralNames issuer() {
    return issuer;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  public static C509AuthorityKeyIdentifier read(CborDecoder in) throws CodecException {
    CborType type = in.peekType();
    if (type.isByteString()) {
      return ofKeyId(in.readByteString());
    }
    in.readArrayLength(3);
    byte[] keyId = C509Cbor.readBytesOrNull(in);
    return ofIssuerAndSerial(keyId, C509GeneralNames.read(in), in.readUnwrappedBigInt());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    if (issuer == null) {
      out.writeByteString(keyId);
      return;
    }
    out.writeArrayStart(3);
    C509Cbor.writeBytesOrNull(out, keyId);
    issuer.encode(out);
    out.writeUnwrappedBiguint(serialNumber);
  }

  @Override
  protected void render(C509TextTree out) {
    out.hex("key id", keyId);
    if (issuer != null) {
      out.item("issuer", issuer).number("serial number", serialNumber);
    }
  }

  @Override
  public String label() {
    return "Authority Key Identifier";
  }

}
