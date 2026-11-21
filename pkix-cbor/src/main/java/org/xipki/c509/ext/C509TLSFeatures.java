// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ext;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Map;

/**
 * The TLS feature extension: an array of TLS extension types.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509TLSFeatures extends C509ExtnValue {

  public static final int SERVER_NAME = 0;
  public static final int MAX_FRAGMENT_LENGTH = 1;
  public static final int STATUS_REQUEST = 5;
  public static final int SUPPORTED_GROUPS = 10;
  public static final int SIGNATURE_ALGORITHMS = 13;
  public static final int USE_SRTP = 14;
  public static final int HEARTBEAT = 15;
  public static final int ALPN = 16;
  public static final int SIGNED_CERTIFICATE_TIMESTAMP = 18;
  public static final int CLIENT_CERTIFICATE_TYPE = 19;
  public static final int SERVER_CERTIFICATE_TYPE = 20;
  public static final int PADDING = 21;
  public static final int PRE_SHARED_KEY = 41;
  public static final int EARLY_DATA = 42;
  public static final int SUPPORTED_VERSIONS = 43;
  public static final int COOKIE = 44;
  public static final int PSK_KEY_EXCHANGE_MODES = 45;
  public static final int CERTIFICATE_AUTHORITIES = 47;
  public static final int OID_FILTERS = 48;
  public static final int POST_HANDSHAKE_AUTH = 49;
  public static final int SIGNATURE_ALGORITHMS_CERT = 50;
  public static final int KEY_SHARE = 51;

  private static final Map<Integer, String> NAMES = Map.ofEntries(
      Map.entry(SERVER_NAME, "server_name"),
      Map.entry(MAX_FRAGMENT_LENGTH, "max_fragment_length"),
      Map.entry(STATUS_REQUEST, "status_request"),
      Map.entry(SUPPORTED_GROUPS, "supported_groups"),
      Map.entry(SIGNATURE_ALGORITHMS, "signature_algorithms"),
      Map.entry(USE_SRTP, "use_srtp"),
      Map.entry(HEARTBEAT, "heartbeat"),
      Map.entry(ALPN, "application_layer_protocol_negotiation"),
      Map.entry(SIGNED_CERTIFICATE_TIMESTAMP, "signed_certificate_timestamp"),
      Map.entry(CLIENT_CERTIFICATE_TYPE, "client_certificate_type"),
      Map.entry(SERVER_CERTIFICATE_TYPE, "server_certificate_type"),
      Map.entry(PADDING, "padding"),
      Map.entry(PRE_SHARED_KEY, "pre_shared_key"),
      Map.entry(EARLY_DATA, "early_data"),
      Map.entry(SUPPORTED_VERSIONS, "supported_versions"),
      Map.entry(COOKIE, "cookie"),
      Map.entry(PSK_KEY_EXCHANGE_MODES, "psk_key_exchange_modes"),
      Map.entry(CERTIFICATE_AUTHORITIES, "certificate_authorities"),
      Map.entry(OID_FILTERS, "oid_filters"),
      Map.entry(POST_HANDSHAKE_AUTH, "post_handshake_auth"),
      Map.entry(SIGNATURE_ALGORITHMS_CERT, "signature_algorithms_cert"),
      Map.entry(KEY_SHARE, "key_share"));

  private final int[] features;

  public C509TLSFeatures(int... features) {
    if (features == null || features.length == 0) {
      throw new IllegalArgumentException("features must not be empty");
    }
    for (int f : features) {
      if (f < 0) {
        throw new IllegalArgumentException("negative feature " + f);
      }
    }
    this.features = features.clone();
  }

  public int[] features() {
    return features.clone();
  }

  /**
   * Returns the name of a TLS extension type, or null if unknown.
   */
  public static String nameOf(int feature) {
    return NAMES.get(feature);
  }

  public static C509TLSFeatures read(CborDecoder in) throws CodecException {
    return new C509TLSFeatures(in.readInts());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(features.length);
    for (int f : features) {
      out.writeLong(f);
    }
  }

  @Override
  protected void render(C509TextTree out) {
    for (int f : features) {
      out.line(NAMES.getOrDefault(f, "unknown") + " (" + f + ")");
    }
  }

  @Override
  public String label() {
    return "TLS Features";
  }

}
