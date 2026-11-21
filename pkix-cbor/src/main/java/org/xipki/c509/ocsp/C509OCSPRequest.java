// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.InsertionOrderedMap;

import java.util.List;

/**
 * A C509 OCSP request. The encoding is an array whose first element is the request kind.
 *
 * @author Lijun Liao (xipki)
 */
public interface C509OCSPRequest {

  /**
   * The request kinds.
   */
  enum Kind {
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
      throw new CodecException("unknown OCSP request kind " + code);
    }
  }

  Kind kind();

  int hashAlgorithm();

  /** The nonce, or null. */
  byte[] nonce();

  C509Extensions extensions();

  InsertionOrderedMap<C509HashedId, List<C509SingleCertRequest>> getRequestedCerts();

  byte[] getEncoded() throws CodecException;

  static C509OCSPRequest read(CborDecoder in) throws CodecException {
    int length = in.readArrayLength();
    Kind kind = Kind.ofCode(in.readInt());
    if (kind == Kind.SIMPLE) {
      return C509SimpleOCSPRequest.readRest(in, length);
    } else {
      return C509BasicOCSPRequest.readRest(in, length);
    }
  }

  static C509OCSPRequest parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509OCSPRequest::read);
  }

  static void checkLength(Kind kind, int actual, int expected) throws CodecException {
    if (actual != expected) {
      throw new CodecException(kind + " OCSP request: array length " + actual + " != "
          + expected);
    }
  }

}
