// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.test;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.xipki.c509.cert.C509Certificate;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.c509.name.C509Name;
import org.xipki.c509.name.C509RdnAttribute;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.c509.registry.ConstRDNAttributeType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Issues one certificate per RDN attribute type and checks that the subject survives the
 * round trip.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Parameterized.class)
public class CertificateSubjectTest {

  private static C509KeyPair caKey;

  private static C509Certificate ca;

  private final long type;

  private final String value;

  private final boolean withCommonName;

  public CertificateSubjectTest(String name, long type, String value, boolean withCommonName) {
    this.type = type;
    this.value = value;
    this.withCommonName = withCommonName;
  }

  @Parameterized.Parameters(name = "{0}")
  public static List<Object[]> cases() {
    Object[][] table = {
        {ConstRDNAttributeType.businessCategory, "my-business-category"},
        {ConstRDNAttributeType.country, "DE"},
        {ConstRDNAttributeType.dmdName, "my-dmdName"},
        {ConstRDNAttributeType.dnQualifier, "my-dnQualifier"},
        {ConstRDNAttributeType.domainComponent, "my-domainComponent"},
        {ConstRDNAttributeType.generationQualifier, "my-generationQualifier"},
        {ConstRDNAttributeType.givenName, "my-givenName"},
        {ConstRDNAttributeType.initials, "my-initials"},
        {ConstRDNAttributeType.jurisdictionCountryName, "DE"},
        {ConstRDNAttributeType.jurisdictionStateOrProvinceName, "my-state"},
        {ConstRDNAttributeType.jurisdictionLocalityName, "my-locality"},
        {ConstRDNAttributeType.locality, "my-locality"},
        {ConstRDNAttributeType.name, "my-name"},
        {ConstRDNAttributeType.organization, "my-organization"},
        {ConstRDNAttributeType.organizationIdentifier, "my-organizationIdentifier"},
        {ConstRDNAttributeType.organizationalUnit, "my-organizationalUnit"},
        {ConstRDNAttributeType.postalCode, "my-postalCode"},
        {ConstRDNAttributeType.pseudonym, "my-pseudonym"},
        {ConstRDNAttributeType.serialNumber, "my-serialNumber"},
        {ConstRDNAttributeType.state, "my-state"},
        {ConstRDNAttributeType.street, "my-streetAddress"},
        {ConstRDNAttributeType.surname, "my-surname"},
        {ConstRDNAttributeType.telephoneNumber, "my-telephoneNumber"},
        {ConstRDNAttributeType.title, "my-title"},
        {ConstRDNAttributeType.unstructuredAddress, "my-unstructuredAddress"},
        {ConstRDNAttributeType.unstructuredName, "my-unstructuredName"},
        {ConstRDNAttributeType.userid, "my-userid"}};

    List<Object[]> cases = new ArrayList<>();
    for (Object[] row : table) {
      long type = (Long) row[0];
      cases.add(new Object[] {ConstRDNAttributeType.name(type), type, row[1], true});
    }
    cases.add(new Object[] {"commonName only", ConstRDNAttributeType.commonName,
        "my-commonName", false});
    return cases;
  }

  @BeforeClass
  public static void createCa() throws Exception {
    caKey = TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1);
    ca = Fixtures.rootCa(caKey, "C=DE, CN=Subject Test CA");
  }

  @Test
  public void issue() throws Exception {
    List<C509RdnAttribute> rdns = new ArrayList<>(Arrays.asList(
        new C509RdnAttribute(type, value)));
    if (withCommonName) {
      rdns.add(new C509RdnAttribute(ConstRDNAttributeType.commonName,
          ConstRDNAttributeType.name(type) + " Test"));
    }
    C509Name subject = new C509Name(rdns);
    C509Certificate cert = Fixtures.issue(caKey, ca, subject,
        TestKeys.generate(ConstPublicKeyAlgorithm.ec_secp256r1).subjectPublicKey(), null, null);
    Assert.assertEquals(subject, cert.subject());
    Assert.assertEquals(ca.subject(), cert.issuer());
    Assert.assertArrayEquals(ca.extensions().subjectKeyId(), cert.extensions().authorityKeyId());
  }

}
