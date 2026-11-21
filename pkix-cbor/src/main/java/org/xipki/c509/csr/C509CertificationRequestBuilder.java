// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.csr;

import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509Attributes;
import org.xipki.c509.attr.C509ExtensionRequest;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509Extensions;
import org.xipki.c509.ext.C509ExtnValue;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.crypto.AtomicContentSigner;
import org.xipki.codec.util.Args;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds C509 certification requests. Requested extensions are sorted by ID and placed into an
 * extension request attribute after all other attributes.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509CertificationRequestBuilder {

  private final C509Name subject;

  private final C509SubjectPublicKey publicKey;

  private final List<C509Attribute> attributes = new ArrayList<>();

  private final List<C509Extension> extensions = new ArrayList<>();

  private C509CertificationRequestBuilder(C509Name subject, C509SubjectPublicKey publicKey) {
    this.subject = Args.notNull(subject, "subject");
    this.publicKey = Args.notNull(publicKey, "publicKey");
  }

  public static C509CertificationRequestBuilder of(
      C509Name subject, C509SubjectPublicKey publicKey) {
    return new C509CertificationRequestBuilder(subject, publicKey);
  }

  public C509CertificationRequestBuilder attribute(C509Attribute attribute) {
    attributes.add(Args.notNull(attribute, "attribute"));
    return this;
  }

  public C509CertificationRequestBuilder extension(C509Extension extension) {
    extensions.add(Args.notNull(extension, "extension"));
    return this;
  }

  public C509CertificationRequestBuilder extension(long id, boolean critical, C509ExtnValue value) {
    return extension(new C509Extension(id, critical, value));
  }

  public C509TBSCertificationRequest body(int signatureAlgorithm) {
    List<C509Attribute> all = new ArrayList<>(attributes);
    if (!extensions.isEmpty()) {
      all.add(new C509Attribute(ConstAttributeType.extensionRequest,
              new C509ExtensionRequest(C509Extensions.sorted(extensions))));
    }
    return new C509TBSCertificationRequest(C509TBSCertificationRequest.TYPE_NATIVE,
        signatureAlgorithm, subject, publicKey, new C509Attributes(all));
  }

  public C509CertificationRequest build(AtomicContentSigner signer) throws SignatureException {
    C509TBSCertificationRequest body = body(signer.c509Algorithm());
    return new C509CertificationRequest(body, signer.atomicC509Sign(body.getEncoded()));
  }

}
