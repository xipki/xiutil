// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.CodecException;

import java.security.SignatureException;
import java.time.Instant;
import java.util.Map;

/**
 * A C509 OCSP response. The encoding is an array whose first element is the response kind.
 *
 * @author Lijun Liao (xipki)
 */
public interface C509OCSPResponse {

  /**
   * The response kinds.
   */
  enum Kind {
    ERROR(0),
    BASIC(1),
    SIMPLE(2);

    private final int code;

    Kind(int code) {
      this.code = code;
    }

    public int code() {
      return code;
    }

    public static Kind ofCode(int code) throws CodecException {
      for (Kind k : values()) {
        if (k.code == code) {
          return k;
        }
      }
      throw new CodecException("unknown OCSP response kind " + code);
    }
  }

  Kind kind();

  byte[] getEncoded() throws CodecException;

  int hashAlgorithm();

  int signatureAlgorithm();

  SignatureValue signature();

  byte[] nonce();

  C509HashedId responderHash();

  Instant producedAt();

  C509Extensions extensions();

  C509CertChainVariant responderCerts();

  Map<C509HashedId, C509CertStatusInfos> getCertStatuses();

  boolean verify(ContentVerifierFactory factory) throws SignatureException;

  static C509OCSPResponse read(CborDecoder in) throws CodecException {
    int length = in.readArrayLength();
    Kind kind = Kind.ofCode(in.readInt());
    switch (kind) {
      case ERROR:
        return C509ErrorOCSPResponse.readRest(in, length);
      case BASIC:
        return C509BasicOCSPResponse.readRest(in, length);
      default:
        return C509SimpleOCSPResponse.readRest(in, length);
    }
  }

  static C509OCSPResponse parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509OCSPResponse::read);
  }

  static void checkLength(Kind kind, int actual, int expected) throws CodecException {
    if (actual != expected) {
      throw new CodecException(kind + " OCSP response: array length " + actual + " != "
          + expected);
    }
  }

}
