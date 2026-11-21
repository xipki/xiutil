// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.util.InsertionOrderedMap;

import java.math.BigInteger;
import java.util.List;

/**
 * C509SimpleOCSPRequest for one certificate (draft-liao-cose-c509-revocation-01, Section 7.4.1).
 *
 * <pre>
 * C509SimpleOCSPRequest = [
 *   ocspRequestType    : 2, ; int16
 *   hashAlgorithm      : IntAlgorithmIdentifier,
 *   nonce              : bytes .size (16..128) / null,
 *   issuerCertHash     : HashedId20,
 *   serialNumber       : bytes .size (1..20),
 *   extensions         : IntExtensions
 * ]
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509SimpleOCSPRequest extends C509CborItem implements C509OCSPRequest {

  private static final int LENGTH = 6;

  private final int hashAlgorithm;

  private final byte[] nonce;

  private final C509HashedId issuerHash;

  private final BigInteger serialNumber;

  private final C509Extensions extensions;

  public C509SimpleOCSPRequest(
      int hashAlgorithm, byte[] nonce, C509HashedId issuerHash,
      BigInteger serialNumber, C509Extensions extensions) {
    this.hashAlgorithm = hashAlgorithm;
    this.nonce = C509Cbor.copy(nonce);
    this.issuerHash = Args.notNull(issuerHash, "issuerHash");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    this.extensions = extensions == null ? C509Extensions.EMPTY : extensions;
  }

  @Override
  public Kind kind() {
    return Kind.SIMPLE;
  }

  @Override
  public int hashAlgorithm() {
    return hashAlgorithm;
  }

  @Override
  public byte[] nonce() {
    return C509Cbor.copy(nonce);
  }

  public C509HashedId issuerHash() {
    return issuerHash;
  }

  public BigInteger serialNumber() {
    return serialNumber;
  }

  @Override
  public C509Extensions extensions() {
    return extensions;
  }

  @Override
  public InsertionOrderedMap<C509HashedId, List<C509SingleCertRequest>> getRequestedCerts() {
    InsertionOrderedMap<C509HashedId, List<C509SingleCertRequest>> r = new InsertionOrderedMap<>();
    r.put(issuerHash, List.of(new C509SingleCertRequest(serialNumber, null)));
    return r;
  }

  static C509SimpleOCSPRequest readRest(CborDecoder in, int length) throws CodecException {
    C509OCSPRequest.checkLength(Kind.SIMPLE, length, LENGTH);
    int hashAlg = in.readInt();
    byte[] nonce = C509Cbor.readBytesOrNull(in);
    C509HashedId issuerHash = new C509HashedId(in.readByteString());
    BigInteger serialNumber = new BigInteger(1, in.readByteString());
    return new C509SimpleOCSPRequest(
        hashAlg, nonce, issuerHash, serialNumber, C509Extensions.read(in));
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(LENGTH);
    out.writeLong(Kind.SIMPLE.code());
    out.writeInt(hashAlgorithm);
    C509Cbor.writeBytesOrNull(out, nonce);
    out.writeByteString(issuerHash.raw());
    out.writeByteString(BigIntegers.asUnsignedByteArray(serialNumber));
    extensions.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("kind", kind())
        .kv("hash algorithm", ConstRegistry.HASH_ALGORITHM.describe(hashAlgorithm))
        .hex("nonce", nonce)
        .kv("issuer hash", issuerHash)
        .kv("serial number", "0x" + serialNumber.toString(16))
        .item("extensions", extensions);
  }

}
