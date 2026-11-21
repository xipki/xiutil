// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

/**
 * The change subject name attribute, the C509 counterpart of the CMC ChangeSubjectName
 * (RFC 6402), as defined in draft-liao-ace-est-c509, Section 4.2:
 * <pre>
 * C509ChangeSubjectName = [
 *   subject     C509Name / null,
 *   subjectAlt  SubjectAltName / null
 * ]
 * </pre>
 * At least one of subject and subjectAlt is present.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509ChangeSubjectName extends C509AttrValue {

  private final C509Name subject;

  private final C509AltName subjectAlt;

  /**
   * @param subject    the new subject, or null to keep it.
   * @param subjectAlt the new subject alternative name, or null to keep it.
   * @throws IllegalArgumentException if both are null.
   */
  public C509ChangeSubjectName(C509Name subject, C509AltName subjectAlt) {
    if (subject == null && subjectAlt == null) {
      throw new IllegalArgumentException("subject and subjectAlt must not be both null");
    }
    this.subject = subject;
    this.subjectAlt = subjectAlt;
  }

  /** The new subject, or null. */
  public C509Name subject() {
    return subject;
  }

  /** The new subject alternative name, or null. */
  public C509AltName subjectAlt() {
    return subjectAlt;
  }

  public static C509ChangeSubjectName read(CborDecoder in) throws CodecException {
    in.readArrayLength(2);
    C509Name subject = C509Cbor.orNull(in, C509Name::read);
    C509AltName subjectAlt = C509Cbor.orNull(in, C509AltName::read);
    if (subject == null && subjectAlt == null) {
      throw new CodecException("change subject name: subject and subjectAlt are both null");
    }
    return new C509ChangeSubjectName(subject, subjectAlt);
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeObjects(subject, subjectAlt);
  }

  @Override
  protected void render(C509TextTree out) {
    out.kv("subject", subject == null ? null : subject.getNameText())
        .item("subjectAlt", subjectAlt);
  }

  @Override
  public String label() {
    return "Change Subject Name";
  }

}
