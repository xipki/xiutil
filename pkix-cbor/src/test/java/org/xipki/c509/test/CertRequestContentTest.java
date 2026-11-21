// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.xipki.c509.attr.C509Attribute;
import org.xipki.c509.attr.C509ChallengePassword;
import org.xipki.c509.attr.C509ChangeSubjectName;
import org.xipki.c509.attr.C509PrivateKeyPossessionStatement;
import org.xipki.c509.base.C509ObjectId;
import org.xipki.c509.base.C509OtherName;
import org.xipki.c509.ext.C509AltName;
import org.xipki.c509.ext.C509ASIdentifiers;
import org.xipki.c509.ext.C509BasicConstraints;
import org.xipki.c509.ext.C509ExtKeyUsageSyntax;
import org.xipki.c509.ext.C509Extension;
import org.xipki.c509.ext.C509NullExtnValue;
import org.xipki.c509.ext.C509InfoAccess;
import org.xipki.c509.ext.C509AccessDescription;
import org.xipki.c509.ext.C509InhibitAnyPolicy;
import org.xipki.c509.ext.C509NameConstraints;
import org.xipki.c509.ext.C509CertificatePolicies;
import org.xipki.c509.ext.C509PolicyQualifierInfo;
import org.xipki.c509.ext.C509PolicyConstraints;
import org.xipki.c509.ext.C509PolicyMappings;
import org.xipki.c509.ext.C509SubjectKeyIdentifier;
import org.xipki.c509.ipres.C509ASIdOrRange;
import org.xipki.c509.name.C509GeneralName;
import org.xipki.c509.name.C509GeneralNames;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.registry.ConstCertificatePolicy;
import org.xipki.c509.csr.C509CertificationRequest;
import org.xipki.c509.dump.C509Dumper;
import org.xipki.c509.name.C509IssuerAndSerialNumber;
import org.xipki.c509.name.C509Name;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Certification requests with one kind of content each: attributes, or requested extensions.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Parameterized.class)
public class CertRequestContentTest {

  private final String subject;

  private final List<C509Attribute> attributes;

  private final List<C509Extension> extensions;

  public CertRequestContentTest(
      String label, String subject, List<C509Attribute> attributes,
      List<C509Extension> extensions) {
    this.subject = subject;
    this.attributes = attributes;
    this.extensions = extensions;
  }

  private static void add(List<Object[]> cases, String label, C509Extension... extensions) {
    cases.add(new Object[] {label, "CN=CSR test", List.of(), List.of(extensions)});
  }

  private static void add(List<Object[]> cases, String label, C509Attribute attribute) {
    cases.add(new Object[] {label, "CN=CSR test", List.of(attribute), List.of()});
  }

  @Parameterized.Parameters(name = "{0}")
  public static List<Object[]> cases() {
    List<Object[]> cases = new ArrayList<>();
    add(cases, "nothing requested");

    add(cases, "challengePassword", new C509Attribute(ConstAttributeType.challengePassword,
        new C509ChallengePassword("my password")));
    add(cases, "privateKeyPossessionStatement",
        new C509Attribute(ConstAttributeType.privateKeyPossessionStatement,
            new C509PrivateKeyPossessionStatement(
                new C509IssuerAndSerialNumber(new C509Name("CN=dummy"), BigInteger.ONE))));
    add(cases, "changeSubjectName subject",
        new C509Attribute(ConstAttributeType.changeSubjectName,
            new C509ChangeSubjectName(new C509Name("C=DE,CN=new subject"), null)));
    add(cases, "changeSubjectName subjectAlt",
        new C509Attribute(ConstAttributeType.changeSubjectName,
            new C509ChangeSubjectName(null, C509AltName.of(C509GeneralName.dns("new.example")))));
    add(cases, "changeSubjectName both",
        new C509Attribute(ConstAttributeType.changeSubjectName,
            new C509ChangeSubjectName(new C509Name("CN=new subject"), C509AltName.of(
                C509GeneralName.dns("a.example"), C509GeneralName.dns("b.example")))));

    add(cases, "subjectKeyIdentifier",
        C509Extension.nonCritical(ConstExtensionId.subjectKeyIdentifier,
            new C509SubjectKeyIdentifier(Fixtures.bytes(20, 1))));
    add(cases, "basicConstraints",
        C509Extension.critical(ConstExtensionId.basicConstraints, C509BasicConstraints.END_ENTITY));
    for (int pathLen = 0; pathLen <= 1; pathLen++) {
      add(cases, "basicConstraints CA " + pathLen,
          C509Extension.critical(ConstExtensionId.basicConstraints,
              C509BasicConstraints.ca(pathLen)));
    }
    add(cases, "basicConstraints CA unlimited",
        C509Extension.critical(ConstExtensionId.basicConstraints,
            C509BasicConstraints.UNLIMITED_CA));
    add(cases, "extendedKeyUsage", C509Extension.nonCritical(ConstExtensionId.extKeyUsage,
        new C509ExtKeyUsageSyntax(ConstExtendedKeyUsage.serverAuth,
            ConstExtendedKeyUsage.clientAuth)));
    add(cases, "inhibitAnyPolicy",
        C509Extension.nonCritical(ConstExtensionId.inhibitAnyPolicy, new C509InhibitAnyPolicy(1)));
    add(cases, "policyMappings", C509Extension.nonCritical(ConstExtensionId.policyMappings,
        C509PolicyMappings.of(
        new C509PolicyMappings.Mapping(1, 2), new C509PolicyMappings.Mapping(3, 4))));
    add(cases, "policyConstraints",
        C509Extension.nonCritical(ConstExtensionId.policyConstraints,
            new C509PolicyConstraints(1, 2)),
        C509Extension.nonCritical(ConstExtensionId.inhibitAnyPolicy, new C509InhibitAnyPolicy(0)));
    add(cases, "policyConstraints without inhibit",
        C509Extension.nonCritical(ConstExtensionId.policyConstraints, new C509PolicyConstraints(1,
            null)));
    add(cases, "policyConstraints without require",
        C509Extension.nonCritical(ConstExtensionId.policyConstraints,
            new C509PolicyConstraints(null, 2)));

    C509GeneralNames permitted = C509GeneralNames.of(C509GeneralName.dns("permitted.dns1"),
        C509GeneralName.dns("permitted.dns2"));
    C509GeneralNames excluded = C509GeneralNames.of(C509GeneralName.dns("excluded.dns1"),
        C509GeneralName.dns("excluded.dns2"));
    add(cases, "nameConstraints", C509Extension.nonCritical(ConstExtensionId.nameConstraints,
        new C509NameConstraints(permitted, excluded)));
    add(cases, "nameConstraints permitted only",
        C509Extension.nonCritical(ConstExtensionId.nameConstraints,
        new C509NameConstraints(permitted, null)));
    add(cases, "nameConstraints excluded only",
        C509Extension.nonCritical(ConstExtensionId.nameConstraints,
        new C509NameConstraints(null, excluded)));

    add(cases, "ocspNoCheck",
        C509Extension.nonCritical(ConstExtensionId.ocsp_nocheck, C509NullExtnValue.INSTANCE));
    add(cases, "certificatePolicies",
        C509Extension.nonCritical(ConstExtensionId.certificatePolicies,
        C509CertificatePolicies.of(
            C509CertificatePolicies.Policy.of(ConstCertificatePolicy.individual_validated),
            C509CertificatePolicies.Policy.of(ConstCertificatePolicy.anyPolicy,
                C509PolicyQualifierInfo.cps("http://cps.url"),
                C509PolicyQualifierInfo.userNotice("this is the user notice")))));
    add(cases, "asIdentifiers", C509Extension.nonCritical(ConstExtensionId.autonomousSysIds,
        C509ASIdentifiers.of(C509ASIdOrRange.id(1), C509ASIdOrRange.range(2, 3))));
    add(cases, "asIdentifiers starting with a range", C509Extension.nonCritical(
        ConstExtensionId.autonomousSysIds, C509ASIdentifiers.of(C509ASIdOrRange.range(2, 3),
            C509ASIdOrRange.id(7))));
    add(cases, "asIdentifiers inherit",
        C509Extension.nonCritical(ConstExtensionId.autonomousSysIds, C509NullExtnValue.INSTANCE));
    add(cases, "subjectInfoAccess", C509Extension.nonCritical(ConstExtensionId.subjectInfoAccess,
        C509InfoAccess.of(new C509AccessDescription(ConstAccessMethod.caIssuers,
            "http://caissuers.url"))));

    C509AltName altName = C509AltName.of(
        C509GeneralName.directory(new C509Name("C=DE,CN=Test")),
        C509GeneralName.dns("abc.com"),
        C509GeneralName.rfc822("abc@example.org"),
        C509GeneralName.smtpUtf8Mailbox("smtputf8@mailbox.org"),
        C509GeneralName.uri("http://myuril.com/abc"),
        C509GeneralName.registeredId(C509ObjectId.of("1.2.3.4")),
        C509GeneralName.ip(Fixtures.bytes(4, 0x11)),
        C509GeneralName.ip(Fixtures.bytes(16, 0xAB)),
        C509GeneralName.otherName(new C509OtherName(C509ObjectId.of("1.2.3.4"), Fixtures.bytes(10,
            0x22))),
        C509GeneralName.hardwareModuleName(
            new C509OtherName(C509ObjectId.of("1.2.3.5"), Fixtures.bytes(16, 0x33))));
    add(cases, "subjectAltName",
        C509Extension.nonCritical(ConstExtensionId.subjectAltName, altName));

    cases.add(new Object[] {"empty subject", "", List.of(), List.of(
        C509Extension.nonCritical(ConstExtensionId.subjectAltName, C509AltName.of(
            C509GeneralName.directory(new C509Name("C=DE,CN=Test")),
            C509GeneralName.dns("abc.com"))))});
    return cases;
  }

  @Test
  public void request() throws Exception {
    C509CertificationRequest csr = Fixtures.request(
        TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1), new C509Name(subject), b -> {
          attributes.forEach(b::attribute);
          extensions.forEach(b::extension);
        });

    ByteArrayOutputStream dump = new ByteArrayOutputStream();
    C509Dumper.of(C509Dumper.Doc.CERT_REQUEST, csr).print(dump);
    Assert.assertTrue("dump", dump.size() > 0);

    Assert.assertEquals(attributes, csr.attributes().asList().stream()
        .filter(a -> a.type() != ConstAttributeType.extensionRequest)
        .collect(Collectors.toList()));

    if (extensions.isEmpty()) {
      Assert.assertNull(csr.requestedExtensions());
    } else {
      Assert.assertEquals(extensions.size(), csr.requestedExtensions().size());
      for (C509Extension e : extensions) {
        Assert.assertEquals(e, csr.requestedExtensions().get(e.id()));
      }
    }
  }

}
