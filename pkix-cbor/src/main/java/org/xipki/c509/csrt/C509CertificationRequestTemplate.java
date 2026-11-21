// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csrt;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;

/**
 * A certification request template (draft-ietf-cose-cbor-encoded-cert-21, Section 4.4).
 *
 * <pre>
 * C509CertificationRequestTemplate = [
 *   c509CertificationRequestTemplateType: int,
 *   c509CertificationRequestType: [+ int] / undefined,
 *   subjectSignatureAlgorithm: [+ AlgorithmIdentifier] / undefined,
 *   subject: NameTemplate / undefined,
 *   subjectPublicKeyAlgorithm: [+ AlgorithmIdentifier] / undefined,
 *   subjectPublicKey: undefined,
 *   extensionsRequest: ExtensionsTemplate / undefined,
 * ]
 * </pre>
 *
 * Each element except the template type may be undefined; the public key is always undefined.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificationRequestTemplate extends C509CborItem {

  public static final int TYPE_SIMPLE = 0;

  private final int[] requestTypes;

  private final C509AlgorithmList signatureAlgorithms;

  private final C509NameTemplate subject;

  private final C509AlgorithmList keyAlgorithms;

  private final C509ExtensionsTemplate extensions;

  /**
   * All arguments are optional (null means undefined).
   */
  public C509CertificationRequestTemplate(
      int[] requestTypes, C509AlgorithmList signatureAlgorithms,
      C509NameTemplate subject, C509AlgorithmList keyAlgorithms,
      C509ExtensionsTemplate extensions) {
    if (requestTypes != null && requestTypes.length == 0) {
      throw new IllegalArgumentException("requestTypes must not be empty");
    }
    this.requestTypes = C509Cbor.copyInts(requestTypes);
    this.signatureAlgorithms = signatureAlgorithms;
    this.subject = subject;
    this.keyAlgorithms = keyAlgorithms;
    this.extensions = extensions;
  }

  public int templateType() {
    return TYPE_SIMPLE;
  }

  public int[] requestTypes() {
    return C509Cbor.copyInts(requestTypes);
  }

  public C509AlgorithmList signatureAlgorithms() {
    return signatureAlgorithms;
  }

  public C509NameTemplate subject() {
    return subject;
  }

  public C509AlgorithmList keyAlgorithms() {
    return keyAlgorithms;
  }

  public C509ExtensionsTemplate extensions() {
    return extensions;
  }

  public static C509CertificationRequestTemplate read(CborDecoder in) throws CodecException {
    in.readArrayLength(7);
    int type = in.readInt();
    if (type != TYPE_SIMPLE) {
      throw new CodecException("unsupported template type " + type);
    }
    int[] requestTypes = C509Cbor.orUndefined(in, CborDecoder::readInts);
    C509AlgorithmList sigAlgs = C509Cbor.orUndefined(in,
        x -> C509AlgorithmList.read(x, ConstRegistry.SIGNATURE_ALGORITHM));
    C509NameTemplate subject = C509Cbor.orUndefined(in, C509NameTemplate::read);
    C509AlgorithmList keyAlgs = C509Cbor.orUndefined(in,
        x -> C509AlgorithmList.read(x, ConstRegistry.PUBLIC_KEY_ALGORITHM));
    in.readUndefined();
    return new C509CertificationRequestTemplate(requestTypes, sigAlgs, subject, keyAlgs,
        C509Cbor.orUndefined(in, C509ExtensionsTemplate::read));
  }

  public static C509CertificationRequestTemplate parse(byte[] encoded) throws CodecException {
    return C509Cbor.parse(encoded, C509CertificationRequestTemplate::read);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(7);
    out.writeInt(TYPE_SIMPLE);
    if (requestTypes == null) {
      out.writeUndefined();
    } else {
      out.writeInts(requestTypes);
    }
    C509Cbor.writeOrUndefined(out, signatureAlgorithms);
    C509Cbor.writeOrUndefined(out, subject);
    C509Cbor.writeOrUndefined(out, keyAlgorithms);
    out.writeUndefined();
    C509Cbor.writeOrUndefined(out, extensions);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("template type", TYPE_SIMPLE)
        .kv("request types", requestTypes == null ? null : Arrays.toString(requestTypes))
        .item("signature algorithms", signatureAlgorithms)
        .item("subject", subject)
        .item("public key algorithms", keyAlgorithms)
        .item("extensions", extensions);
  }

  @Override
  protected String getTitle() {
    return "C509 Certification Request Template";
  }

}
