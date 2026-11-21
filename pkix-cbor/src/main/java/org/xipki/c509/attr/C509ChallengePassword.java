// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;


/**
 * The challenge password attribute. The text form never shows the password.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ChallengePassword extends C509AttrValue {

  private final String password;

  public C509ChallengePassword(String password) {
    this.password = Args.notNull(password, "password");
  }

  public String password() {
    return password;
  }

  public static C509ChallengePassword read(CborDecoder in) throws CodecException {
    return new C509ChallengePassword(in.readTextString());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeTextString(password);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line("******");
  }

  @Override
  public String label() {
    return "Challenge Password";
  }

}
