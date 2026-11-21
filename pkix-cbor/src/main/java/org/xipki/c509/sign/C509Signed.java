// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.sign;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.crypto.ContentVerifierFactory;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.Args;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

/**
 * A body followed by its signature, encoded as one array: the fields of the body and then the
 * signature value.
 *
 * @param <B> the body type.
 * @author Lijun Liao (xipki)
 */
public abstract class C509Signed<B extends C509SignedBody> extends C509CborItem {

  protected final B body;

  private final SignatureValue signature;

  protected C509Signed(B body, SignatureValue signature) {
    this.body = Args.notNull(body, "body");
    this.signature = Args.notNull(signature, "signature");
  }

  public final B body() {
    return body;
  }

  public final SignatureValue signature() {
    return signature;
  }

  public final int signatureAlgorithm() {
    return body.signatureAlgorithm();
  }

  /**
   * Returns the encoding without the enclosing array header.
   */
  public final byte[] getUnwrappedEncoded() {
    byte[] tbs = body.getEncoded();
    byte[] sig = signature.getEncoded();
    byte[] out = new byte[tbs.length + sig.length];
    System.arraycopy(tbs, 0, out, 0, tbs.length);
    System.arraycopy(sig, 0, out, tbs.length, sig.length);
    return out;
  }

  /**
   * @param factory the verifier factory.
   */
  public final boolean verify(ContentVerifierFactory factory)
      throws SignatureException {
    try {
      return factory.getForC509(signatureAlgorithm())
              .atomicC509Verify(body.getEncoded(), signature);
    } catch (GeneralSecurityException | GenerationException e) {
      throw new SignatureException("could not verify the signature of "
          + getClass().getSimpleName(), e);
    }
  }

  /**
   * Reads the signature value that follows a body.
   */
  protected static SignatureValue readSignature(CborDecoder in, C509SignedBody body)
      throws CodecException {
    return SignatureValue.read(body.signatureAlgorithm(), in);
  }

  @Override
  protected final void writeTo(CborEncoder out) throws CodecException {
    out.writeArrayStart(body.fieldCount() + 1);
    body.encode(out);
    signature.encode(out);
  }

  @Override
  protected void render(C509TextTree out) {
    out.inline(body).external("signature", signature);
  }

}
