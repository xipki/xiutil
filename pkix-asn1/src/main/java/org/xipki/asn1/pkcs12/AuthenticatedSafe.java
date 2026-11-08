// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.pkcs12;

import org.xipki.asn1.cms.ContentInfo;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * RFC 7292:
 * <pre>
 *    AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 *        -- Data if unencrypted
 *        -- EncryptedData if password-encrypted
 *        -- EnvelopedData if public key-encrypted
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AuthenticatedSafe extends ContentInfo.Seq0 {

  public AuthenticatedSafe(ContentInfo... entries) {
    super(entries);
  }

  public AuthenticatedSafe(List<ContentInfo> entries) {
    super(entries);
  }

  private AuthenticatedSafe(Asn1Sequence seq) throws CodecException {
    super(seq);
  }

  public static AuthenticatedSafe fromAsn1(Asn1Sequence seq) throws CodecException {
    return new AuthenticatedSafe(seq);
  }

  public static AuthenticatedSafe fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

}
