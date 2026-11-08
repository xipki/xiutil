// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.x509;

import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * Implementation of the RoleSyntax object as specified by the RFC3281.
 *
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::=
 *
 * RoleSyntax ::= SEQUENCE {
 *     roleAuthority  [0] GeneralNames OPTIONAL,
 *     roleName       [1] GeneralName
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RoleSyntax extends Asn1Encodable {

  private final GeneralNames roleAuthority;
  private final GeneralName roleName;

  public RoleSyntax(GeneralNames roleAuthority, GeneralName roleName) {
    this.roleAuthority = roleAuthority;
    this.roleName = Args.notNull(roleName, "roleName");

    Asn1IA5String uri = roleName.getUri();
    if(uri == null || uri.getString().isEmpty()) {
      throw new IllegalArgumentException("the role name MUST be non empty and MUST " +
          "use the URI option of GeneralName");
    }
  }

  public RoleSyntax(GeneralName roleName) {
    this(null, roleName);
  }

  public RoleSyntax(String roleName) {
    this(null,
        GeneralName.ofUri(new Asn1IA5String(Args.notBlank(roleName, "roleName"))));
  }

  public static RoleSyntax fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    int index = 0;
    GeneralNames roleAuthority = seq.isNotTaggedAt(index, 0) ? null
        : GeneralNames.fromAsn1(seq.getSequenceTaggedAt(index++, false));

    Asn1Util.checkSequenceEnd(index, size - 1);
    GeneralName roleName =
        GeneralName.fromAsn1(seq.getTaggedAt(index, 1).getExplicitTaggedBase());
    return new RoleSyntax(roleAuthority, roleName);
  }

  public GeneralNames getRoleAuthority() {
    return this.roleAuthority;
  }

  public GeneralName getRoleName() {
    return this.roleName;
  }

  public String getRoleNameAsString() {
    Asn1Encodable o = this.roleName.getValue();
    return (o instanceof AbstractAsn1String) ? ((AbstractAsn1String) o).getString() : o.toString();
   }

  public String[] getRoleAuthorityAsString() {
    if(roleAuthority == null) {
      return new String[0];
    }

    String[] namesString = new String[roleAuthority.size()];
    for(int i = 0; i < roleAuthority.size(); i++) {
      Asn1Encodable value = roleAuthority.get(i).getValue();
      if(value instanceof AbstractAsn1String) {
        namesString[i] = ((AbstractAsn1String)value).getString();
      } else {
        namesString[i] = value.toString();
      }
    }
    return namesString;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(
        roleAuthority == null ? null : Asn1TaggedObject.newImplicit(0, roleAuthority),
        Asn1TaggedObject.newExplicit(1, roleName));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (roleAuthority != null) {
      roleAuthority.toStringWithLineSep(buf, indentLevel, "roleAuthority", true);
    }

    roleName.toStringWithLineSep(buf, indentLevel, "roleName", true);

    return deleteLastNewLine(buf);
  }

}
