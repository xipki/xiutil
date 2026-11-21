// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.ocsp;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.c509.cert.CoseC509;
import org.xipki.c509.registry.ConstCertificateType;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.crypto.EmbedCertsMode;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The certificate chain of the signer of an OCSP message, in one of several encodings,
 * selected by the certificate type.
 *
 * <pre>
 * CertChainVariant = [
 *   type  : uint .le 255,
 *   chain : any,
 * ]
 * </pre>
 * <ul>
 *   <li>type 0 (X.509): the chain is a COSE_X509: one DER-encoded certificate as byte string,
 *       or an array of them.</li>
 *   <li>type 4 (C509): the chain is a {@link CoseC509}.</li>
 *   <li>other types: the chain is kept as {@link CborEncodedItem}.</li>
 * </ul>
 * The type values are taken from the "TLS Certificate Types" registry, see
 * {@link ConstCertificateType}.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertChainVariant extends C509CborItem {

  private final int type;

  /**
   * List&lt;byte[]&gt; for {@link ConstCertificateType#x509}, {@link CoseC509} for
   * {@link ConstCertificateType#c509}, otherwise {@link CborEncodedItem}.
   */
  private final Object chain;

  private C509CertChainVariant(int type, Object chain) {
    this.type = type;
    this.chain = chain;
  }

  public static C509CertChainVariant ofC509(CoseC509 certs) {
    return new C509CertChainVariant(ConstCertificateType.c509, Args.notNull(certs, "certs"));
  }

  /**
   * @param derCerts the DER-encoded X.509 certificates, signer certificate first.
   */
  public static C509CertChainVariant ofX509(List<byte[]> derCerts) {
    if (derCerts == null || derCerts.isEmpty()) {
      throw new IllegalArgumentException("derCerts must not be empty");
    }
    List<byte[]> copy = new ArrayList<>(derCerts.size());
    for (byte[] c : derCerts) {
      copy.add(Args.notNull(c, "derCerts element").clone());
    }
    return new C509CertChainVariant(ConstCertificateType.x509, Collections.unmodifiableList(copy));
  }

  /**
   * Creates a chain of a type other than X.509 and C509.
   *
   * @param type  the type, between 0 and 255, but not 0 or 4, see
   *              {@link ConstCertificateType}.
   * @param chain the chain as {@link CborEncodedItem}, or generic CBOR data, see
   *              {@link CborEncodedItem#ofData(Object)}.
   */
  public static C509CertChainVariant ofOther(int type, Object chain) {
    if (type < 0 || type > 255) {
      throw new IllegalArgumentException("type out of range [0, 255]: " + type);
    }
    if (type == ConstCertificateType.x509 || type == ConstCertificateType.c509) {
      throw new IllegalArgumentException("use the dedicated factory method for type " + type);
    }
    Args.notNull(chain, "chain");
    return new C509CertChainVariant(type, CborEncodedItem.ofData(chain));
  }

  /**
   * Selects the certificates of a signer to embed into a signed OCSP message.
   *
   * @param mode  which certificates: none, the signer certificate only, or the signer
   *              certificate and its issuers up to, but excluding, the self-signed root.
   * @param certs the certificates of the signer, signer certificate first.
   * @return the selected certificates, or null for none.
   */
  static C509CertChainVariant select(EmbedCertsMode mode, CoseC509 certs) {
    if (mode == null || mode == EmbedCertsMode.NONE) {
      return null;
    }
    if (certs.size() == 1) {
      return ofC509(certs);
    }
    if (mode == EmbedCertsMode.CERT) {
      return ofC509(CoseC509.of(certs.first()));
    }

    List<C509Certificate> chain = new ArrayList<>(certs.size());
    chain.add(certs.first());
    for (C509Certificate c : certs.certificates().subList(1, certs.size())) {
      if (c.isSelfSigned()) {
        break;
      }
      chain.add(c);
    }
    return ofC509(new CoseC509(chain));
  }

  /** The certificate type, see {@link ConstCertificateType}. */
  public int type() {
    return type;
  }

  public boolean isC509() {
    return type == ConstCertificateType.c509;
  }

  /** The C509 certificates if the type is {@link ConstCertificateType#c509}, otherwise null. */
  public CoseC509 c509() {
    return type == ConstCertificateType.c509 ? (CoseC509) chain : null;
  }

  /**
   * The DER-encoded X.509 certificates if the type is {@link ConstCertificateType#x509},
   * otherwise null.
   */
  @SuppressWarnings("unchecked")
  public List<byte[]> x509() {
    if (type != ConstCertificateType.x509) {
      return null;
    }
    List<byte[]> certs = (List<byte[]>) chain;
    List<byte[]> copy = new ArrayList<>(certs.size());
    certs.forEach(c -> copy.add(c.clone()));
    return copy;
  }

  /** The chain if the type is not one of X.509 and C509, otherwise null. */
  public CborEncodedItem raw() {
    return (chain instanceof CborEncodedItem) ? (CborEncodedItem) chain : null;
  }

  public static C509CertChainVariant read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    long type = in.readLong();
    if (type < 0 || type > 255) {
      throw new CodecException("CertChainVariant: type out of range [0, 255]: " + type);
    }

    try {
      if (type == ConstCertificateType.x509) {
        if (in.peekType().isArray()) {
          return ofX509(C509Cbor.readArray(in, CborDecoder::readByteString));
        } else {
          return ofX509(List.of(in.readByteString()));
        }
      } else if (type == ConstCertificateType.c509) {
        return ofC509(CoseC509.read(in));
      } else {
        return new C509CertChainVariant((int) type, in.readEncodedItem());
      }
    } catch (IllegalArgumentException e) {
      throw new CodecException("CertChainVariant: " + e.getMessage(), e);
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(2);
    out.writeLong(type);
    if (type == ConstCertificateType.x509) {
      // COSE_X509: a single certificate is encoded as byte string, not as array.
      List<byte[]> certs = (List<byte[]>) chain;
      if (certs.size() > 1) {
        out.writeArrayStart(certs.size());
      }
      for (byte[] c : certs) {
        out.writeByteString(c);
      }
    } else if (type == ConstCertificateType.c509) {
      ((CoseC509) chain).encode(out);
    } else {
      ((CborEncodedItem) chain).encode(out);
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  protected void render(C509TextTree out) {
    out.kv("type", ConstCertificateType.describe(type));
    if (type == ConstCertificateType.x509) {
      ((List<byte[]>) chain).forEach(c -> out.hex("X.509 certificate", c));
    } else if (type == ConstCertificateType.c509) {
      out.inline((CoseC509) chain);
    } else {
      out.kv("chain", ((CborEncodedItem) chain).toDiagnostic());
    }
  }

}
