// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.name.C509IssuerAndSerialNumber;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * The private key possession statement attribute
 * (draft-ietf-cose-cbor-encoded-cert-21, Section 4.3.3).
 *
 * <pre>
 * PrivateKeyPossessionStatement = [
 *   issuer: Name,
 *   certificateSerialNumber: CertificateSerialNumber,
 *   cert: C509CertData / null,
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509PrivateKeyPossessionStatement extends C509AttrValue {

  private final C509IssuerAndSerialNumber signer;

  private final byte[] cert;

  public C509PrivateKeyPossessionStatement(C509IssuerAndSerialNumber signer, byte[] cert) {
    this.signer = Args.notNull(signer, "signer");
    this.cert = C509Cbor.copy(cert);
  }

  public C509PrivateKeyPossessionStatement(C509IssuerAndSerialNumber signer) {
    this(signer, null);
  }

  public C509IssuerAndSerialNumber signer() {
    return signer;
  }

  /** The encoded certificate, or null. */
  public byte[] cert() {
    return C509Cbor.copy(cert);
  }

  public static C509PrivateKeyPossessionStatement read(CborDecoder in) throws CodecException {
    in.readArrayLength(3);
    C509Name issuer = C509Name.read(in);
    C509IssuerAndSerialNumber signer =
        new C509IssuerAndSerialNumber(issuer, in.readUnwrappedBigInt());
    return new C509PrivateKeyPossessionStatement(signer, C509Cbor.readBytesOrNull(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(3);
    signer.issuer().encode(out);
    out.writeUnwrappedBiguint(signer.serialNumber());
    C509Cbor.writeBytesOrNull(out, cert);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("issuer", signer.issuer().getNameText())
        .kv("serial number", "0x" + signer.serialNumber().toString(16))
        .hex("certificate", cert);
  }

  @Override
  public String label() {
    return "Private Key Possession Statement";
  }

}
